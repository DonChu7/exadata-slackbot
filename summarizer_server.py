#!/usr/bin/env python3
from __future__ import annotations
from typing import Any, Dict, Optional
import os
from mcp.server.fastmcp import FastMCP
import summarizer_agent_lc as lc
import summarizer_agent as sa  # manual/structured summarizer

# optional .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

app = FastMCP("summarizer-mcp")

# ---------- allowlist ----------
def _is_allowed_path(path: str) -> bool:
    if not path:
        return False
    allow = os.getenv("SUMMARIZER_FILE_ALLOWLIST", "")
    if not allow.strip():
        return True
    seps = ";" if ";" in allow else ":"
    prefixes = [p.strip() for p in allow.split(seps) if p.strip()]
    ap = os.path.abspath(path)
    return any(ap.startswith(os.path.abspath(p)) for p in prefixes)

# ---------- tools (manual engine) ----------
@app.tool()
def health() -> Dict[str, Any]:
    return sa.health()

@app.tool()
def summarize_text(text: str, style_hint: Optional[str] = None) -> Dict[str, Any]:
    """Summarize plain text (manual engine)."""
    return sa.summarize_text(text, style_hint=style_hint)

@app.tool()
def summarize_pdf_file(path: str, style_hint: Optional[str] = None) -> Dict[str, Any]:
    """Summarize a local PDF file (manual engine)."""
    if not _is_allowed_path(path):
        return {"error": "path not allowed by SUMMARIZER_FILE_ALLOWLIST"}
    return sa.summarize_pdf_path(path, style_hint=style_hint)

@app.tool()
def summarize_pdf_b64(pdf_b64: str, style_hint: Optional[str] = None) -> Dict[str, Any]:
    """Summarize a PDF passed as base64 (manual engine)."""
    return sa.summarize_pdf_b64(pdf_b64, style_hint=style_hint)

# ---------- tools (LangChain engine) ----------
@app.tool()
def lc_health() -> Dict[str, Any]:
    return lc.health()

@app.tool()
def lc_summarize_text(text: str) -> Dict[str, Any]:
    return lc.lc_summarize_text(text)

@app.tool()
def lc_summarize_pdf_file(path: str) -> Dict[str, Any]:
    if not _is_allowed_path(path):
        return {"error": "path not allowed by SUMMARIZER_FILE_ALLOWLIST"}
    return lc.lc_summarize_pdf_path(path)

@app.tool()
def lc_summarize_pdf_b64(pdf_b64: str) -> Dict[str, Any]:
    return lc.lc_summarize_pdf_b64(pdf_b64)

# ---------- manifest ----------
@app.tool()
def tool_manifest() -> Dict[str, Any]:
    return {
        "service": "summarizer-mcp",
        "tools": [
            {
                "name": "lc_summarize_text",
                "description": "Summarize pasted text with LangChain summarize chain.",
                "intents": ["summarize", "tl;dr", "summary"],
                "patterns": [r"\bsummarize\b(?!.*\bpdf\b)"]  # summarize (no explicit 'pdf')
            },
            {
                "name": "lc_summarize_pdf_b64",
                "description": "Summarize a PDF (bytes as base64) with LangChain summarize chain.",
                "intents": ["summarize pdf"],
                "patterns": [
                    r"\bsummarize\b.*\bpdf\b",
                    r"\bsummarize\b.*\b(attachment|file)\b"
                ]
            }
        ]
    }

# ---------- explicit tool map (optional) ----------
TOOLS = {
    "health": health,
    # Manual engine
    "summarize_text": summarize_text,
    "summarize_pdf_file": summarize_pdf_file,
    "summarize_pdf_b64": summarize_pdf_b64,
    # LangChain engine
    "lc_health": lc_health,
    "lc_summarize_text": lc_summarize_text,
    "lc_summarize_pdf_file": lc_summarize_pdf_file,
    "lc_summarize_pdf_b64": lc_summarize_pdf_b64,
    # Back-compat aliases (optional)
    # "lc_summarize_text": summarize_text,          
    # "lc_summarize_pdf_b64": summarize_pdf_b64,     
}

if __name__ == "__main__":
    app.run()
