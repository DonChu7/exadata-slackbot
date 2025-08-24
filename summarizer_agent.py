# summarizer_agent.py
from __future__ import annotations
import io
import os
import time
import base64 as b64
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List

# Models
from langchain_ollama import OllamaLLM
from langchain.text_splitter import RecursiveCharacterTextSplitter

# PDF
from pypdf import PdfReader


# --------- Tunables (env overrideable) ----------
CHUNK_SIZE        = int(os.getenv("SUMMARIZER_CHUNK_SIZE", "2000"))
CHUNK_OVERLAP     = int(os.getenv("SUMMARIZER_CHUNK_OVERLAP", "200"))
FAST_TEXT_LIMIT   = int(os.getenv("SUMMARIZER_FAST_TEXT_LIMIT", "2000"))
MAX_SUMMARY_CHUNKS= int(os.getenv("SUMMARIZER_MAX_CHUNKS", "8"))
OLLAMA_MODEL      = os.getenv("OLLAMA_MODEL", "mistral")

# Prompts (same spirit as your app.py)
SINGLE_PROMPT_TMPL = """You are summarizing an internal runbook/spec for Exascale on KVM and OEDACLI clone workflows.
Return a concise, engineering-ready summary using ONLY the provided text (no guessing). If something is missing, say "not specified".

Structure your output exactly as:
### Overview
- What this doc is about and the main outcome.

### Preconditions / Environment
- Clusters/roles, node types (EGS vs non-EGS), required files (OEDA es.xml), versions/flags, and any gating checks.

### Where It Fits in the Flow
- Call sites and step names (e.g., CREATE_GUEST, CREATE_USERS, CELL_CONNECTIVITY) and any specific functions to invoke.

### Procedure (numbered)
1) Step… (include function names, APIs, or scripts if present)
2) Step…
- Keep steps high-signal and in order.

### Commands & Syntax (verbatim where possible)
- Show key OEDACLI snippets or shell lines in a fenced code block.
- Normalize placeholders like SRCNAME, TGTNAME, STEPNAME, ADMINNET, PRIVNET, ILOMNET, INTERCONNECT, CLIENTNET, PARENT.
- 8–20 lines max.

### Validation / Health Checks
- What to verify (services, EDV/EGS readiness, wallets/certs, network/IPs), and expected results.

### Known Issues / Bugs
- List explicit caveats and bug IDs/links if present.

### Risks / Gotchas
- Short bullets of things likely to break (versions, flags, EDV/ASM compat, side effects).

### Post-Actions / Limits
- What is NOT handled by this flow and what must be done manually.

### References
- Any links or doc names found in the text.

Keep total output ~250–400 words + one code block. Preserve exact CLI capitalization. If code/commands aren’t present, state “not specified”.

Passage:
{chunk}
"""

MAP_PROMPT_TMPL = """You are extracting high-signal bullets from an Exascale/KVM + OEDACLI cloning doc chunk.
Use ONLY the given text. Be terse and technical.

Return bullets under these labels when present:
- Scope/Outcome: …
- Preconditions/Env: …
- Step/Callsite: … (e.g., CREATE_GUEST) ; Function/API: …
- Commands: … (OEDACLI or shell; include 1–4 representative lines if present)
- Parameters: … (SRCNAME, TGTNAME, STEPNAME, ADMINNET/PRIVNET/ILOMNET/INTERCONNECT/CLIENTNET, PARENT, flags)
- Validation: … (services ready, EDV, wallets/certs, IPs)
- KnownIssues/Bugs: … (IDs/links)
- Risks/Gotchas: …
- PostActions/Limits: …
- Refs: … (URLs/doc names)

Rules:
- Quote commands verbatim; no invented values.
- Prefer one line per bullet; keep each ≤140 chars.
- If a category isn’t in the chunk, omit it.

Chunk:
{chunk}
"""

REDUCE_PROMPT_TMPL = """You are producing the final engineering summary based on bullet lists from multiple chunks.
Synthesize ONLY what’s present in the bullets (no guessing). Keep it compact and ready to execute.

Output format:
### Overview
… 2–4 sentences.

### Preconditions / Environment
- …

### Where It Fits in the Flow
- … (explicit step names/functions)

### Procedure (numbered)
1) …
2) …
3) …

### Commands & Syntax
```text
# key OEDACLI / shell lines (8–20 lines max), normalize placeholders:
# SRCNAME, TGTNAME, STEPNAME, ADMINNET, PRIVNET, ILOMNET, INTERCONNECT, CLIENTNET, PARENT, TYPE, etc.
### Validation / Health Checks
…
### Known Issues / Bugs
…
### Risks / Gotchas
…
### Post-Actions / Limits
…
### References
…
Keep body ~250–450 words plus the single code block. If bullets conflict, prefer the most specific/recent statements. If a section has no data, write “not specified”.

Bullet inputs:
{bullets}
"""


# ------------- Core engine -------------
_llm: Optional[OllamaLLM] = None

def _get_llm() -> OllamaLLM:
    global _llm
    if _llm is None:
        _llm = OllamaLLM(model=OLLAMA_MODEL)
    return _llm

def _call_llm(prompt: str, retries: int = 2, backoff: float = 0.8) -> str:
    last_err = None
    llm = _get_llm()
    for i in range(retries + 1):
        try:
            return (llm.invoke(prompt) or "").strip()
        except Exception as e:
            last_err = e
            if i < retries:
                time.sleep(backoff * (2 ** i))
    raise last_err

def _chunk_text(text: str) -> List[str]:
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", " ", ""],
    )
    return splitter.split_text(text)

def summarize_text_manual(text: str, style_hint: Optional[str] = None) -> Tuple[str, str]:
    """Returns (summary, notes)."""
    t0 = time.perf_counter()
    try:
        if len(text) <= FAST_TEXT_LIMIT:
            prompt = SINGLE_PROMPT_TMPL.format(chunk=text[:4000])
            if style_hint:
                prompt = f"(Style: {style_hint})\n\n{prompt}"
            out = _call_llm(prompt)
            t1 = time.perf_counter()
            return out, f"timing: single={t1 - t0:.2f}s"
        # map→reduce
        chunks = _chunk_text(text)
        if len(chunks) > MAX_SUMMARY_CHUNKS:
            chunks = chunks[:MAX_SUMMARY_CHUNKS]

        bullets_all = []
        for idx, c in enumerate(chunks, 1):
            mp = MAP_PROMPT_TMPL.format(chunk=c[:4000])
            if style_hint:
                mp = f"(Style: {style_hint})\n\n{mp}"
            out = _call_llm(mp)
            bullets_all.append(f"--- chunk {idx} ---\n{(out or '').strip()}")

        combined = "\n".join(bullets_all)[:8000]
        rp = REDUCE_PROMPT_TMPL.format(bullets=combined, title="document")
        if style_hint:
            rp = f"(Style: {style_hint})\n\n{rp}"
        final = _call_llm(rp)
        t2 = time.perf_counter()
        return final, f"timing: mapreduce={t2 - t0:.2f}s"
    except Exception as e:
        return f"[Summarization failed]\n{type(e).__name__}: {e}", f"error: {type(e).__name__}: {e}"

def summarize_pdf_bytes(pdf_bytes: bytes, style_hint: Optional[str] = None) -> Tuple[str, int, str]:
    """Returns (summary, pages, notes)."""
    t0 = time.perf_counter()
    reader = PdfReader(io.BytesIO(pdf_bytes))
    pages = len(reader.pages)
    parts = []
    for p in reader.pages:
        parts.append(p.extract_text() or "")
    text = ("\n".join(parts)).strip()
    t1 = time.perf_counter()
    if len(text) < 200:
        return "[No extractable text — likely a scanned/image-only PDF.]", pages, f"timing: extract={t1 - t0:.2f}s"
    summary, notes = summarize_text_manual(text, style_hint=style_hint)
    notes = (notes + f" | extract={t1 - t0:.2f}s").strip()
    return summary, pages, notes


# ------------- Public agent API -------------
def health() -> Dict[str, Any]:
    try:
        _ = _get_llm()
        return {"ok": True, "model": OLLAMA_MODEL}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def summarize_text(text: str, style_hint: Optional[str] = None) -> Dict[str, Any]:
    if not text or not text.strip():
        return {"error": "empty text"}
    summary, notes = summarize_text_manual(text, style_hint=style_hint)
    return {"summary": summary, "notes": notes}

def summarize_pdf_path(path: str, style_hint: Optional[str] = None) -> Dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {"error": f"file not found: {path}"}
    try:
        with open(path, "rb") as f:
            pdf_bytes = f.read()
        summary, pages, notes = summarize_pdf_bytes(pdf_bytes, style_hint=style_hint)
        return {"summary": summary, "pages": pages, "notes": notes}
    except Exception as e:
        return {"error": str(e)}

def summarize_pdf_b64(b64_str: str, style_hint: str | None = None) -> Dict[str, Any]:
    try:
        pdf_bytes = base64.b64decode(b64_str)
    except Exception as e:
        return {"error": f"invalid base64: {e}"}
    summary, pages, notes = summarize_pdf_bytes(pdf_bytes, style_hint=style_hint)
    return {"summary": summary, "pages": pages, "notes": notes}
