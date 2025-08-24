# exa23ai_rag_server.py
#!/usr/bin/env python3
from __future__ import annotations
try:
    from dotenv import load_dotenv  
    load_dotenv() 
except Exception:
    pass
from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP
import traceback

import exa23ai_rag_agent as rag

app = FastMCP("oracle23ai-rag-mcp")

@app.tool()
def health() -> Dict[str, Any]:
    try:
        rag.init_once()
        return rag.health()
    except Exception as e:
        return {"ok": False, "error": str(e), "trace": traceback.format_exc()[:2000]}

@app.tool()
def rag_query(question: str, k: int = 3) -> Dict[str, Any]:
    """
    Ask a question over the Oracle 23ai Vector Store.
    Returns:
      {"answer": str, "sources": [{"title","source","score","chunk_preview"}...]}
    """
    try:
        rag.init_once()
        return rag.query(question, k=k)
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()[:2000]}

@app.tool()
def rag_upsert_text(doc_id: str, text: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Upsert a plain-text document into the vector store.
    """
    try:
        rag.init_once()
        return rag.upsert_text(doc_id, text, **(metadata or {}))
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()[:2000]}

@app.tool()
def rag_delete(doc_id: str) -> Dict[str, Any]:
    try:
        rag.init_once()
        return rag.delete(doc_id)
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()[:2000]}

@app.tool()
def tool_manifest() -> Dict[str, Any]:
    return {
        "service": "oracle23ai-rag-mcp",
        "tools": [
            {
                "name": "rag_query",
                "description": "Answer Exadata/infra questions grounded in Oracle 23ai vector store.",
                "intents": ["question", "ask", "help", "why", "how"],
                "patterns": []
            }
        ]
    }

if __name__ == "__main__":
    app.run()
