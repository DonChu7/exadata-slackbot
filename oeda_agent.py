# oeda_agent.py
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List

# ========== Live migration detection ==========
LIVE_MIG_PAT = re.compile(r"\blive[-\s]*migration\b", re.I)

def is_live_migration_req(user_request: str) -> bool:
    return bool(LIVE_MIG_PAT.search(user_request or ""))

# ========== Host parsing helpers ==========

# Simple, global scans across the entire request (no tokenization needed)
# 1) Direct IDs in FQDNs, e.g. ...adm03.us..., ...celadm07.us...
ADM_ID     = re.compile(r"(?<!cel)adm(\d{2})(?!\d)", re.I)     # avoid 'celadm'
CELADM_ID  = re.compile(r"celadm(\d{2})(?!\d)", re.I)

# 2) Ranges within the same token, e.g. celadm04-06 or adm03-05
ADM_RANGE  = re.compile(r"(?<!cel)adm(\d{2})\s*-\s*(\d{2})", re.I)
CEL_RANGE  = re.compile(r"celadm(\d{2})\s*-\s*(\d{2})", re.I)

# 3) Concatenated pairs, e.g. adm0304, celadm0708
ADM_PAIR   = re.compile(r"(?<!cel)adm(\d{4,})", re.I)          # even length blocks
CEL_PAIR   = re.compile(r"celadm(\d{4,})", re.I)

def _expand(a: int, b: int) -> List[int]:
    step = 1 if b >= a else -1
    return list(range(a, b + step, step))

def _pairs_to_ids(s: str) -> List[int]:
    # split into 2‑digit chunks: "0304" -> [3,4]
    out: List[int] = []
    if len(s) % 2 != 0:
        return out
    for i in range(0, len(s), 2):
        try:
            out.append(int(s[i:i+2]))
        except ValueError:
            pass
    return out

def _derive_counts_from_hosts(user_request: str) -> Dict[str, int]:
    """
    Extract compute/cell counts & startIds from the raw request text.
    Handles FQDNs, ranges (celadm04-06), and concatenated pairs (adm0304).
    """
    comps, cells = set(), set()
    text = user_request or ""

    # Direct single IDs
    for m in ADM_ID.finditer(text):
        comps.add(int(m.group(1)))
    for m in CELADM_ID.finditer(text):
        cells.add(int(m.group(1)))

    # Ranges
    for m in ADM_RANGE.finditer(text):
        comps.update(_expand(int(m.group(1)), int(m.group(2))))
    for m in CEL_RANGE.finditer(text):
        cells.update(_expand(int(m.group(1)), int(m.group(2))))

    # Concatenated pairs
    for m in ADM_PAIR.finditer(text):
        comps.update(_pairs_to_ids(m.group(1)))
    for m in CEL_PAIR.finditer(text):
        cells.update(_pairs_to_ids(m.group(1)))

    out: Dict[str, int] = {}
    if comps:
        out["computeCount"]   = len(comps)
        out["computeStartId"] = min(comps)
    if cells:
        out["cellCount"]      = len(cells)
        out["cellStartId"]    = min(cells)
    return out

def _rack_prefix(user_request: str) -> Optional[str]:
    # e.g. "scaqaw03adm03..." or "scaqaw03celadm04..." -> "scaqaw03"
    m = re.search(r"(sc[a-z0-9]+)(?=adm|celadm)", user_request)
    return m.group(1) if m else None

# ========== Live migration defaults (NO user_request reference here) ==========

def apply_live_migration_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enforce the minimum required knobs for a live‑migration‑capable env.
      - virtualCluster True
      - exascale True
      - guest storage on celldisk (uniform if only 1 cluster)
    """
    cfg = dict(cfg or {})
    cfg["virtualCluster"] = True
    cfg["exascale"] = True
    cfg.setdefault("clusterCount", 1)

    if "clusterGuestStorage" not in cfg and "clusterStorage" not in cfg:
        if int(cfg.get("clusterCount", 1)) > 1:
            cfg["clusterGuestStorage"] = ",".join(["celldisk"] * int(cfg["clusterCount"]))
        else:
            cfg["guestStorage"] = "celldisk"
    return cfg

# ========== Optional local Transformers path ==========

def _extract_first_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    s = text.strip()
    if s.startswith("```"):
        parts = s.split("```")
        s = "".join(p for p in parts if "{" in p)
    m = re.search(r"\{.*\}", s, flags=re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None

def call_llm_to_generate_json(user_request: str) -> Dict[str, Any]:
    """
    Try local HuggingFace model specified by LOCAL_LLM_MODEL.
    If unavailable/fails, fall back to mock_llm_response.
    """
    model_name = os.environ.get("LOCAL_LLM_MODEL")
    if model_name:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline  # type: ignore
            tok = AutoTokenizer.from_pretrained(model_name)
            mdl = AutoModelForCausalLM.from_pretrained(model_name)
            gen = pipeline("text-generation", model=mdl, tokenizer=tok)

            prompt = (
                "You are an Exadata configuration assistant. "
                "Return ONLY a JSON object with keys: "
                "{rackPrefix: string, computeCount: int, cellCount: int, "
                "computeStartId: int, cellStartId: int, clusterCount?: int, "
                "virtualCluster?: bool, exascale?: bool, qinq?: bool, pkey?: bool}. "
                "Input:\n" + user_request + "\nJSON:"
            )
            out = gen(prompt, max_length=256, num_return_sequences=1, do_sample=False)
            text = out[0]["generated_text"] if out else ""
            parsed = _extract_first_json(text)
            if parsed:
                return parsed
        except Exception as e:
            print(f"[OEDA] Local transformers failed: {e}")

    # Fallback
    return mock_llm_response(user_request)

# ========== Mock path (now with correct counts) ==========

@dataclass
class MinConfig:
    rackPrefix: str
    computeCount: int
    cellCount: int
    computeStartId: int
    cellStartId: int
    clusterCount: Optional[int] = 1
    virtualCluster: Optional[bool] = True
    exascale: Optional[bool] = None
    qinq: Optional[bool] = None
    pkey: Optional[bool] = None

def mock_llm_response(user_request: str) -> Dict[str, Any]:
    """
    Heuristic mock: uses robust host parsing and simple keyword cues.
    """
    result: Dict[str, Any] = {
        "virtualCluster": True,
    }

    # rackPrefix
    rp = _rack_prefix(user_request)
    if rp:
        result["rackPrefix"] = rp

    # counts
    counts = _derive_counts_from_hosts(user_request)
    result.update(counts)

    # vc/baremetal, qinq, exascale/celldisk
    u = (user_request or "").lower()
    if any(w in u for w in ["baremetal", "bare metal", "bare-metal"]):
        result["virtualCluster"] = False

    if "qinq" in u or "secure fabric" in u:
        result["qinq"] = True

    if "exascale" in u or "celldisk" in u or "cell disks" in u:
        result["guestStorage"] = "celldisk"
        result["exascale"] = True

    # cluster count
    cluster_count: Optional[int] = None
    m = re.search(r"(\d+)\s+cluster", u)
    if m:
        cluster_count = int(m.group(1))
    else:
        words = {
            "one":1,"two":2,"three":3,"four":4,"five":5,
            "six":6,"seven":7,"eight":8,"nine":9,"ten":10
        }
        m2 = re.search(r"\b(" + "|".join(words.keys()) + r")\s+cluster", u)
        if m2:
            cluster_count = words[m2.group(1)]

    if result.get("virtualCluster", True):
        result["clusterCount"] = cluster_count or 1
    # else: bare metal → omit clusterCount

    # live migration defaults if requested
    if is_live_migration_req(user_request):
        result = apply_live_migration_defaults(result)

    return result

# ========== genoedaxml runners ==========

def run_genoedaxml_with_log(minconfig: Dict[str, Any], genoedaxml_path: str) -> Tuple[Optional[str], str]:
    """
    Run genoedaxml and return (xml_path, combined_stdout_stderr).
    """
    import time
    if not os.path.isfile(genoedaxml_path):
        msg = f"genoedaxml not found at '{genoedaxml_path}'. Skipping XML generation."
        return None, msg

    genoeda_dir = os.path.dirname(os.path.abspath(genoedaxml_path))
    genconfig_dir = os.path.join(genoeda_dir, "WorkDir", "genconfig")
    os.makedirs(genconfig_dir, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as jf:
        json.dump(minconfig, jf, indent=2)
        json_path = jf.name

    try:
        cp = subprocess.run([genoedaxml_path, json_path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=False)
        out = (cp.stdout or "")
        err = (cp.stderr or "")
        log_text = f"{out}\n{err}".strip()
    finally:
        try: os.unlink(json_path)
        except Exception: pass

    # Find newest *-generated.xml
    newest_path, newest_mtime = None, -1.0
    for root, _, files in os.walk(genconfig_dir):
        for fn in files:
            if fn.endswith("-generated.xml"):
                p = os.path.join(root, fn)
                try:
                    m = os.path.getmtime(p)
                    if m > newest_mtime:
                        newest_mtime, newest_path = m, p
                except Exception:
                    pass

    return (os.path.abspath(newest_path) if newest_path else None), log_text

def run_genoedaxml(minconfig: Dict[str, Any], genoedaxml_path: str) -> Optional[str]:
    xml_path, _ = run_genoedaxml_with_log(minconfig, genoedaxml_path)
    return xml_path

# ========== Optional helpers kept for back‑compat (not used for gating) ==========

_RACK_PAT = re.compile(r"rack\s*description:\s*(?P<desc>.+)", re.I)
_DEDUCED_PAT = re.compile(r"deduced\s+rackDescription\s+to:\s*(?P<desc>.+)", re.I)

def _parse_rack_description(log_text: str) -> Optional[str]:
    for line in (log_text or "").splitlines():
        m = _RACK_PAT.search(line) or _DEDUCED_PAT.search(line)
        if m:
            return m.group("desc").strip()
    return None
