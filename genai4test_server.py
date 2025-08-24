#!/usr/bin/env python3
from __future__ import annotations
import os, json, re, traceback
import requests
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from urllib.parse import quote
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# --- Config via env ---
BASE_URL = os.getenv("GENAI4TEST_BASE_URL",
    "https://phoenix228912.dev3sub3phx.databasede3phx.oraclevcn.com:8000")
VERIFY_SSL = os.getenv("GENAI4TEST_VERIFY_SSL", "false").lower() == "true" \
             or os.getenv("GENAI4TEST_CA_BUNDLE")  # path to CA file if provided
CA_BUNDLE = os.getenv("GENAI4TEST_CA_BUNDLE")  # e.g. /etc/ssl/certs/your-ca.pem
TIMEOUT_S = float(os.getenv("GENAI4TEST_TIMEOUT_S", "600"))
DEFAULT_EMAIL = os.getenv("GENAI4TEST_EMAIL", "dongyang.zhu@oracle.com")
DEFAULT_AGENT = os.getenv("GENAI4TEST_AGENT", "bug_agent")

app = FastMCP("genai4test-mcp")

# ---------------------------
# Routing patterns / intents
# ---------------------------
# 1) A “wide” detector for intent: request to generate/create/help with test for a bug
INTENT_PATTERNS = [
    # can you help me generate the test for bug 12345678
    r"\b(can\s+you\s+help|help\s+me)\b.*\b(generate|create|make)\b.*\b(test|script)\b.*\bbug\s*#?\s*(\d{6,})\b",
    # help me generate test for bug 12345678
    r"\bhelp\s+me\b.*\b(generate|create|make)\b.*\b(test|script)\b.*\bbug\s*#?\s*(\d{6,})\b",
    # create a test for bug 12345678
    r"\b(create|generate|make)\b.*\b(test|script)\b.*\bbug\s*#?\s*(\d{6,})\b",
    # simpler fallback: "... bug 12345678 ..." with "test"
    r"\b(test|script)\b.*\bbug\s*#?\s*(\d{6,})\b",
]

# 2) A focused extractor for the bug number (works on most phrasing)
BUG_EXTRACTOR = r"\b(?:bug\s*#?\s*)?(\d{6,})\b"

@app.tool()
def tool_manifest() -> Dict[str, Any]:
    """
    Expose metadata so your Router can auto-discover this service/tool and
    (optionally) use patterns/examples for rule routing.
    """
    return {
        "service": "genai4test-mcp",
        "tools": [
            {
                "name": "run_bug_test",
                "description": "Generate a test for an Oracle bug via genai4test. Params: bug_no, email, agent",
                "args_schema": {
                    "bug_no": "str (required)",
                    "email":  "str (optional; default env GENAI4TEST_EMAIL)",
                    "agent":  "str (optional; default env GENAI4TEST_AGENT, e.g. bug2tsc/bug_agent/bug_sum_agent)"
                },
                # --- Routing hints ---
                "intents": {
                    "patterns": INTENT_PATTERNS,
                    "slot_extractors": {
                        "bug_no": BUG_EXTRACTOR
                    },
                    "examples": [
                        "can you help me generate the test for bug 35123456",
                        "help me generate test for bug 35123456",
                        "create a test for bug 35123456",
                        "make a test script for bug #35123456",
                    ],
                    # Optional threshold your router can honor for regex-only confidence
                    "confidence_hint": 0.85
                }
            }
        ],
    }

@app.tool()
def health() -> Dict[str, Any]:
    try:
        r = requests.get(f"{BASE_URL}/docs", timeout=TIMEOUT_S, verify=VERIFY_SSL)
        return {"ok": r.ok, "status_code": r.status_code}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

@app.tool()
def classify_intent(text: str) -> Dict[str, Any]:
    """
    Quick rule-based classifier + slot extractor for routing:
    Returns {matched: bool, confidence: float, service, tool, slots: {bug_no}, matched_pattern}
    """
    if not text or not text.strip():
        return {"matched": False, "confidence": 0.0}

    t = text.strip().lower()
    best = None
    for pat in INTENT_PATTERNS:
        m = re.search(pat, t, flags=re.IGNORECASE | re.DOTALL)
        if m:
            best = pat
            break

    if not best:
        return {"matched": False, "confidence": 0.0}

    # Extract bug_no using focused extractor
    m_bug = re.search(BUG_EXTRACTOR, t, flags=re.IGNORECASE | re.DOTALL)
    bug_no = m_bug.group(1) if m_bug else None

    # Simple confidence heuristic: found a pattern + a 6+ digit bug number
    conf = 0.9 if bug_no else 0.7

    return {
        "matched": True,
        "confidence": conf,
        "service": "genai4test-mcp",
        "tool": "run_bug_test",
        "slots": {"bug_no": bug_no},
        "matched_pattern": best,
    }

@app.tool()
def run_bug_test(bug_no: str, email: str | None = None, agent: str | None = None) -> dict:
    """
    Call genai4test to generate a test from a bug.
    Returns: {ok, summary, sql, file_url, request_url, status, error?}
    """
    try:
        bug_no = (bug_no or "").strip()
        if not bug_no:
            return {"ok": False, "error": "bug_no is required"}

        email = (email or DEFAULT_EMAIL).strip()
        agent = (agent or DEFAULT_AGENT).strip()

        # URL-encode path segments safely
        email_q = quote(email, safe="")
        bug_q   = quote(bug_no, safe="")
        agent_q = quote(agent, safe="")

        url = f"{BASE_URL}/genai4test/run-bug/{email_q}/{bug_q}/{agent_q}"
        kwargs = {"timeout": TIMEOUT_S}
        if CA_BUNDLE:
            kwargs["verify"] = CA_BUNDLE
        else:
            kwargs["verify"] = bool(VERIFY_SSL)

        url = f"{BASE_URL}/genai4test/run-bug/{email_q}/{bug_q}/{agent_q}"

        sess = requests.Session()
        sess.trust_env = False                          # ignore proxy env
        sess.proxies = {"http": None, "https": None}    # force no proxy

        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=1.0,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=10, pool_block=True)
        sess.mount("https://", adapter)
        sess.mount("http://", adapter)

        verify_arg = CA_BUNDLE if CA_BUNDLE else bool(VERIFY_SSL)
        timeout_arg = (10, TIMEOUT_S)   # (connect, read). e.g. (10, 600+)

        resp = sess.get(url, timeout=timeout_arg, verify=verify_arg)
        if resp.status_code != 200:
            # include a short body preview to help debug
            body = resp.text[:500]
            return {"ok": False, "status": resp.status_code, "request_url": url,
                    "error": f"HTTP {resp.status_code}", "body": body}

        data = resp.json()
        return {
            "ok": True,
            "request_url": url,
            "summary": data.get("summary"),
            "sql": data.get("sql"),
            "file_url": data.get("file_url"),
        }
    except requests.exceptions.ReadTimeout as e:
        return {"ok": False, "error": f"ReadTimeout: {e}", "request_url": url}
    except requests.exceptions.SSLError as e:
        return {"ok": False, "error": f"SSLError: {e}", "request_url": url}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "request_url": url}

if __name__ == "__main__":
    app.run()
