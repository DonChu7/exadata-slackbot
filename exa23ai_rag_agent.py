# exa23ai_rag_agent.py
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional

import oracledb
from langchain_ollama import OllamaLLM
from langchain.chains import RetrievalQA
from langchain_community.embeddings.oracleai import OracleEmbeddings
from langchain_community.vectorstores.oraclevs import OracleVS
from langchain_community.vectorstores.utils import DistanceStrategy

ORA_USER       = os.getenv("ORA_USER")
ORA_PASSWORD   = os.getenv("ORA_PASSWORD")
ORA_DSN        = os.getenv("ORA_DSN")           # e.g. "host:1521/service"
ORA_TABLE      = os.getenv("ORA_TABLE", "SLACKBOT_VECTORS")
ORA_MODEL_NAME = os.getenv("ORA_MODEL_NAME", "ALL_MINILM_L12_V2")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "mistral")

# --- Singleton state (initialized once) ---
_CONN: Optional[oracledb.Connection] = None
_EMB: Optional[OracleEmbeddings] = None
_VS: Optional[OracleVS] = None
_RETRIEVER = None
_QA = None

def init_once() -> Dict[str, Any]:
    """
    Initialize Oracle connection, embeddings, vector store, retriever, and QA chain.
    Safe to call repeatedly.
    """
    global _CONN, _EMB, _VS, _RETRIEVER, _QA
    if _QA is not None:
        return {"ok": True, "note": "already initialized"}

    if not ORA_USER or not ORA_PASSWORD or not ORA_DSN:
        raise RuntimeError("Missing ORA_USER/ORA_PASSWORD/ORA_DSN.")

    _CONN = oracledb.connect(user=ORA_USER, password=ORA_PASSWORD, dsn=ORA_DSN)
    _EMB = OracleEmbeddings(conn=_CONN, params={"provider": "database", "model": ORA_MODEL_NAME})
    _VS = OracleVS(
        client=_CONN,
        table_name=ORA_TABLE,
        embedding_function=_EMB,
        distance_strategy=DistanceStrategy.COSINE,
    )
    _RETRIEVER = _VS.as_retriever(search_kwargs={"k": 3})
    llm = OllamaLLM(model=OLLAMA_MODEL)
    _QA = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=_RETRIEVER,
        return_source_documents=True,
    )
    # quick health probe
    try:
        _ = _QA.invoke({"query": "health check"})
    except Exception as e:
        # still return initialized; caller can inspect
        return {"ok": False, "error": f"health probe failed: {e}"}
    return {"ok": True}

def health() -> Dict[str, Any]:
    """Return a basic health snapshot."""
    return {
        "oracle_connected": bool(_CONN),
        "table": ORA_TABLE,
        "embed_model": ORA_MODEL_NAME,
        "ollama_model": OLLAMA_MODEL,
        "initialized": bool(_QA),
    }

def query(question: str, k: int = 3) -> Dict[str, Any]:
    """Run a RAG query and return answer + compact sources."""
    if not question or not question.strip():
        return {"error": "empty question"}
    if _QA is None:
        init_once()

    # optionally override k per-call
    if _RETRIEVER and k:
        _RETRIEVER.search_kwargs["k"] = int(k)

    result = _QA.invoke({"query": question})
    answer = result.get("result", "") or ""
    sources = result.get("source_documents", []) or []
    src = []
    for d in sources:
        meta = d.metadata or {}
        src.append({
            "title": meta.get("title") or os.path.basename(meta.get("source","") or "") or "untitled",
            "source": meta.get("source"),
            "score": meta.get("score"),
            "chunk_preview": (d.page_content or "")[:300]
        })
    return {"answer": answer, "sources": src}

def upsert_text(doc_id: str, text: str, **metadata) -> Dict[str, Any]:
    """
    Add/update a text document in the OracleVS table with optional metadata.
    """
    if not text or not text.strip():
        return {"error": "empty text"}
    if _VS is None:
        init_once()
    # OracleVS upsert via from_texts
    docs = [text]
    metadatas = [{**metadata, "id": doc_id}] if doc_id else [{**metadata}]
    _VS.add_texts(texts=docs, metadatas=metadatas, ids=[doc_id] if doc_id else None)
    return {"ok": True, "id": doc_id}

def delete(doc_id: str) -> Dict[str, Any]:
    """Delete a document by id if supported by OracleVS."""
    if _VS is None:
        init_once()
    try:
        _VS.delete(ids=[doc_id])
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}
