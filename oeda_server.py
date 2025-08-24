#!/usr/bin/env python3
"""
MCP server for OEDA generation.

Tools
- generate_minconfig(request: str)
    -> {"minconfig_json": {...}}

- generate_oedaxml(request: str, genoedaxml_path?: str=None, return_xml?: bool=False)
    -> {
         "minconfig_json": {...},
         "es_xml_path": "<path or null>",
         "es_xml_b64": "<base64 or null>"  # only if return_xml=True and file exists
       }

Safety
- Optional allowlist for genoedaxml path via env OEDA_GENOEDAXML_ALLOWLIST (colon/semicolon separated prefixes)
"""

from __future__ import annotations
import os, json, base64, io
from typing import Dict, Any, Optional, List
import subprocess, shlex, re
import sys, contextlib
from mcp.server.fastmcp import FastMCP

# your existing agent
from oeda_agent import call_llm_to_generate_json, run_genoedaxml, run_genoedaxml_with_log
_RACK_PAT1 = re.compile(r"rack\s*description:\s*(?P<desc>.+)", re.I)
_RACK_PAT2 = re.compile(r"deduced\s+rackDescription\s+to:\s*(?P<desc>.+)", re.I)
_XVER_ANY = re.compile(r"\bX\s*(\d+)\b", re.I)
_X_MODEL_RE = re.compile(r"\bX\s*(\d+)", re.I)
ILOM_USER    = os.getenv("OEDA_ILOM_USER", "root")
ILOM_PASS    = os.getenv("OEDA_ILOM_PASS")         # prefer passing via env, not hard-coded
ILOM_TIMEOUT = int(os.getenv("OEDA_ILOM_TIMEOUT", "8"))
ILOM_ENABLED = os.getenv("OEDA_ILOM_SSH", "0") == "1"


_COMPUTE_RE = re.compile(r"\b([a-z0-9\-\.]*?adm\d{2}(?:\.[\w\.-]+)?)\b", re.I)


app = FastMCP("oeda-mcp")


LIVE_MIG_PAT = re.compile(r"\blive[-\s]*migration\b", re.I)

def _first_compute_host(text: str) -> str | None:
    m = _COMPUTE_RE.search(text or "")
    return m.group(1) if m else None

def _ilom_host_for_compute(host: str) -> str:
    # Your naming convention: append "-ilom" before any domain
    if "." in host:
        h, rest = host.split(".", 1)
        return f"{h}-ilom.{rest}"
    return f"{host}-ilom"

_E_MODEL_RE = re.compile(r"\bE(\d+)-(\d+)[A-Z]?\b", re.I)

def _is_x10_or_newer_from_product_name(name: str) -> bool | None:
    """
    Return True if product_name is X10+ or equivalent E-model,
    False if clearly older, None if unknown.
    """
    if not name:
        return None

    # Case 1: "X9-2", "X10M-8", "X11" ...
    xm = _X_MODEL_RE.search(name)
    if xm:
        try:
            return int(xm.group(1)) >= 10
        except ValueError:
            return None

    # Case 2: "E5-2L", "E7-2", ...
    em = _E_MODEL_RE.search(name)
    if em:
        try:
            e_major = int(em.group(1))
            if e_major >= 5:
                return True   # treat E5 and above as X10+
            return False
        except ValueError:
            return None

    return None


def _ssh_run(host: str, cmd: str) -> tuple[int, str, str]:
    """
    Run an ILOM CLI command over SSH. Prefer a forced TTY + stdin feed because
    many ILOM versions don't accept 'ssh host "cmd"' non-interactively.
    """
    base_tty = [
        "ssh",
        "-tt",  # force TTY allocation (twice to force)
        "-o", "StrictHostKeyChecking=no",
        f"{ILOM_USER}@{host}",
    ]
    base_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        f"{ILOM_USER}@{host}",
        cmd,
    ]

    def _run(argv, stdin_text: str | None):
        try:
            p = subprocess.run(
                argv,
                input=stdin_text,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=ILOM_TIMEOUT,
            )
            return p.returncode, p.stdout or "", p.stderr or ""
        except subprocess.TimeoutExpired:
            return 124, "", "SSH timeout"
        except Exception as e:
            return 1, "", f"{type(e).__name__}: {e}"

    # Prefer sshpass when a password is provided
    if ILOM_PASS:
        tty_argv  = ["sshpass", "-p", ILOM_PASS, *base_tty]
        cmd_argv  = ["sshpass", "-p", ILOM_PASS, *base_cmd]
    else:
        # key-based auth: allow BatchMode
        tty_argv  = [*base_tty[:2], *base_tty[2:]]
        cmd_argv  = [*base_cmd[:2], "-o", "BatchMode=yes", *base_cmd[2:]]

    # 1) TTY + stdin path
    rc, out, err = _run(tty_argv, stdin_text=f"{cmd}\nexit\n")
    if rc == 0 and ("product_name" in out.lower() or "->" in out or "/SYS" in out):
        return rc, out, err

    # 2) Fallback to remote command form
    rc2, out2, err2 = _run(cmd_argv, stdin_text=None)
    return rc2, out2, (err if rc2 != 0 else err2)

def _probe_ilom_product_name(raw_request: str) -> tuple[str, str | None, str]:
    """
    Returns (status, product_name, reason)
      status in {"ok","fail","unknown"} for X10+ suitability.
    """
    comp = _first_compute_host(raw_request)
    if not comp:
        return "unknown", None, "No compute host found in request"
    ilom = _ilom_host_for_compute(comp)
    rc, out, err = _ssh_run(ilom, "show /SYS")
    if rc != 0 or not (out or "").strip():
        # try minimal command variant
        rc2, out2, err2 = _ssh_run(ilom, "show product_name")
        out = out2 if (rc2 == 0 and out2) else out
        err = err2 if not out else err
        if rc != 0 and rc2 != 0:
            return "unknown", None, f"ILOM SSH failed: {err or err2 or 'no output'}"

    # Look for 'product_name = ORACLE SERVER E5-2L'
    prod = None
    for line in (out or "").splitlines():
        if "product_name" in line.lower():
            # accept both 'product_name = ...' and 'product_name: ...'
            parts = re.split(r"[:=]\s*", line, maxsplit=1)
            if len(parts) == 2:
                prod = parts[1].strip()
                break
    if not prod:
        return "unknown", None, "No product_name in ILOM output"

    ok = _is_x10_or_newer_from_product_name(prod)
    if ok is True:
        return "ok", prod, "ILOM probe: X10+ equivalent (per E5-2L+ rule)"
    if ok is False:
        return "fail", prod, "ILOM probe: hardware below X10 per product_name"
    return "unknown", prod, "ILOM probe: could not map product_name to X version"


def _is_live_migration_req(text: str) -> bool:
    return bool(LIVE_MIG_PAT.search(text or ""))

def _apply_live_migration_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Enforce required knobs for live-migration-capable env."""
    cfg = dict(cfg or {})
    cfg["virtualCluster"] = True
    cfg["exascale"] = True
    cfg.setdefault("clusterCount", 1)
    # Prefer uniform celldisk unless user already specified per-cluster
    if "clusterGuestStorage" not in cfg and "clusterStorage" not in cfg:
        if int(cfg.get("clusterCount", 1)) > 1:
            cfg["clusterGuestStorage"] = ",".join(["celldisk"] * int(cfg["clusterCount"]))
        else:
            cfg["guestStorage"] = "celldisk"
    return cfg
    

def _extract_x_version(text: str) -> Optional[int]:
    if not text:
        return None
    m = _XVER_ANY.search(text)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _is_allowed_path(path: str) -> bool:
    """
    If OEDA_GENOEDAXML_ALLOWLIST is set, path must start with one of its prefixes.
    e.g. OEDA_GENOEDAXML_ALLOWLIST=/net/dbdevfssmnt-shared01.dev3fss1phx.databasede3phx.oraclevcn.com/exadata_dev_image_oeda
    """
    if not path:
        return False
    allow = os.getenv("OEDA_GENOEDAXML_ALLOWLIST", "")
    if not allow.strip():
        return True  # permissive if unset
    seps = ";" if ";" in allow else ":"
    prefixes = [p.strip() for p in allow.split(seps) if p.strip()]
    path_abs = os.path.abspath(path)
    for pref in prefixes:
        if path_abs.startswith(os.path.abspath(pref)):
            return True
    return False

@app.tool()
def generate_minconfig(request: str) -> Dict[str, Any]:
    """
    Return only minconfig.json from a natural-language request.
    """
    if not isinstance(request, str) or not request.strip():
        return {"error": "Missing or empty 'request' string."}
    cfg = call_llm_to_generate_json(request.strip())
    live_mig = _is_live_migration_req(request)
    if live_mig:
        cfg = _apply_live_migration_defaults(cfg)
    return {"minconfig_json": cfg, "live_migration": live_mig}

@app.tool()
def generate_oedaxml(
    request: str,
    genoedaxml_path: Optional[str] = None,
    return_xml: bool = False,
    force_mock: bool = False,
    debug: bool = True,
) -> Dict[str, Any]:
    """
    Build minconfig via LLM/mock and optionally run genoedaxml to produce es.xml.
    If debug=True, include run logs and discovery notes in the response.
    """
    if not isinstance(request, str) or not request.strip():
        return {"error": "Missing or empty 'request' string."}

    # choose generator
    try:
        if force_mock:
            from oeda_agent import mock_llm_response
            cfg = mock_llm_response(request.strip())
            gen_used = "mock"
        else:
            cfg = call_llm_to_generate_json(request.strip())
            gen_used = "llm"
    except Exception as e:
        return {"error": f"minconfig generation failed: {e}"}

    # Enforce live-migration defaults if requested
    live_mig = _is_live_migration_req(request)
    if live_mig:
        cfg = _apply_live_migration_defaults(cfg)

    out = {
    "minconfig_json": cfg,
    "generator": gen_used,
    "es_xml_path": None,
    "live_migration": live_mig,
    "live_mig_check": "n/a",
    "live_mig_reason": None,
    "rack_desc": None,            # keep for back-compat; now unused
    "ilom_product_name": None,    # NEW: expose what we saw
    }

    if live_mig and ILOM_ENABLED:
        status, prod, reason = _probe_ilom_product_name(request)
        out["ilom_product_name"] = prod
        out["live_mig_check"] = status
        out["live_mig_reason"] = reason
        if status == "fail":
            return out

    # If no genoedaxml path, return JSON only
    if not genoedaxml_path:
        if debug:
            out["note"] = "genoedaxml_path not provided; returning JSON only."
        return out

    # allowlist
    if not _is_allowed_path(genoedaxml_path):
        out["error"] = "genoedaxml_path not allowed by OEDA_GENOEDAXML_ALLOWLIST"
        return out

    # Run genoedaxml and capture stdout/stderr

    buf_out, buf_err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            es_xml_path = run_genoedaxml(cfg, genoedaxml_path)
        out["es_xml_path"] = es_xml_path
    except Exception as e:
        out["error"] = f"genoedaxml failed: {e}"
    finally:
        stdout_text = buf_out.getvalue()
        stderr_text = buf_err.getvalue()
        if debug:
            out["genoedaxml_stdout"] = stdout_text
            out["genoedaxml_stderr"] = stderr_text
        
    log_text = (stdout_text or "")
    if stderr_text:
        log_text = (log_text + "\n" + stderr_text).strip()

    

    # If genoedaxml wrote an error, do NOT trust any es_xml_path that was returned.
    def _extract_oeda_error_line(text: str) -> str | None:
        if not text:
            return None
        for line in text.splitlines():
            if line.strip().startswith("ERROR:"):
                return line.strip()
        # a few common non-prefixed errors you showed
        needles = [
            "Invalid input provided to genoedaxml",
            "OEDA rack description could not be determined",
            "Error running generate and compare OEDA es.xml"
        ]
        for n in needles:
            if n.lower() in text.lower():
                # return a short tail around the phrase
                lines = text.splitlines()
                tail = "\n".join(lines[max(0, len(lines)-8):])
                return tail.strip()
        return None

    err_line = _extract_oeda_error_line(log_text)

    if err_line:
        # surface concise error to the caller/UI
        out["es_error"] = err_line
        # suppress potentially stale XML path/b64
        out["es_xml_path"] = None
        out.pop("es_xml_b64", None)

    # If status == "unknown", do NOT block; return XML if available and include debug so we can investigate.


    # Optionally attach es.xml content
    if return_xml and out.get("es_xml_path") and os.path.isfile(out["es_xml_path"]):
        try:
            with open(out["es_xml_path"], "rb") as f:
                out["es_xml_b64"] = base64.b64encode(f.read()).decode("ascii")
        except Exception as e:
            out["es_xml_b64_error"] = f"Failed to read es.xml: {e}"

    
    log_text = (stdout_text or "")
    if stderr_text:
        log_text = (log_text + "\n" + stderr_text).strip()

    # If no XML was generated, extract a concise error line
    if not out.get("es_xml_path"):
        err_line = None
        for line in (log_text or "").splitlines():
            if "ERROR:" in line:
                err_line = line.strip()
                break
        # fallback to a short tail if no explicit "ERROR:" found
        if not err_line:
            tail = "\n".join((log_text or "").splitlines()[-8:])
            err_line = tail.strip() or "genoedaxml failed with no diagnostic output."

        out["es_error"] = err_line

    return out

@app.tool()
def tool_manifest() -> Dict[str, Any]:
    return {
        "service": "oeda-mcp",
        "tools": [
            {
                "name": "generate_oedaxml",
                "description": "Generate OEDA es.xml and/or minconfig.json from natural language.",
                "intents": ["oeda", "oedaxml", "es.xml", "exadata xml", "generate xml"],
                "patterns": [r"\bgenerate\s+oedaxml\b", r"\bconfig+xml\b", r"\boeda\b", r"\bxml\b"]
            }
        ]
    }


if __name__ == "__main__":
    app.run()