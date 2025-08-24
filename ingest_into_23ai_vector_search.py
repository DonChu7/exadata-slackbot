#!/usr/bin/env python3
"""
Ingest PDFs + URLs into Oracle 23ai Vector Store (OracleVS).
Defaults to Oracle in-database embeddings (model 'ALL_MINILM_L12_V2').
Optionally uses HuggingFace embeddings if --provider hf is chosen.

Requirements:
  pip install oracledb langchain-community langchain-core langchain pypdf pymupdf unstructured
"""

import os
import sys
import argparse
import json
import time
import glob

# DB
import oracledb

# LangChain loaders/splitters
from langchain_community.document_loaders import PyPDFLoader, UnstructuredURLLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

# Embeddings
from langchain_community.embeddings.oracleai import OracleEmbeddings
from langchain_huggingface import HuggingFaceEmbeddings

# Vector store
from langchain_community.vectorstores.oraclevs import OracleVS
from langchain_community.vectorstores.utils import DistanceStrategy
from langchain_community.vectorstores import oraclevs as oraclevs_utils

# Optional title extraction
try:
    import fitz  # PyMuPDF
except Exception:
    fitz = None


DEFAULT_URLS = [
    "https://www.oracle.com/database/technologies/exadata/exascale/",
    "https://blogs.oracle.com/exadata/post/exadata-x11m",
    "https://blogs.oracle.com/exadata/post/exadata252",
]

DEFAULT_PDFS = sorted(glob.glob(os.path.join("pdfs", "**", "*.pdf"), recursive=True))


def parse_args():
    p = argparse.ArgumentParser(description="Ingest docs into Oracle 23ai Vector Store via LangChain.")
    # DB connect
    p.add_argument("--user", default=os.getenv("ORA_USER"), help="DB username (or ORA_USER)")
    p.add_argument("--password", default=os.getenv("ORA_PASSWORD"), help="DB password (or ORA_PASSWORD)")
    p.add_argument("--dsn", default=os.getenv("ORA_DSN"), help="EZConnect DSN host:port/service (or ORA_DSN)")
    # Embedding provider
    p.add_argument("--provider", choices=["database", "hf"], default="database",
                   help="Embedding provider: 'database' uses OracleEmbeddings; 'hf' uses HuggingFace in Python.")
    p.add_argument("--model-name", default=None,
                   help="Model name. For provider=database default is ALL_MINILM_L12_V2; for hf default is sentence-transformers/all-MiniLM-L6-v2.")
    # Data sources
    p.add_argument("--urls", nargs="*", default=None, help="URLs to ingest (space-separated). Default: built-in list.")
    p.add_argument("--pdfs", nargs="*", default=None, help="PDF file paths (space-separated). Default: built-in list.")
    # Chunking
    p.add_argument("--chunk-size", type=int, default=1000, help="Chunk size")
    p.add_argument("--chunk-overlap", type=int, default=200, help="Chunk overlap")
    # Vector store table
    p.add_argument("--table-name", required=True, help="Target Oracle table name (created if not exists).")
    p.add_argument("--distance", choices=["cosine", "dot", "euclidean"], default="cosine", help="Distance strategy.")
    # Indexing
    p.add_argument("--index", choices=["none", "hnsw", "ivf"], default="none", help="Create ANN index after ingest.")
    p.add_argument("--index-name", default=None, help="Index name (default auto-generated).")
    p.add_argument("--index-accuracy", type=int, default=None, help="Index accuracy hint (e.g., 90).")
    p.add_argument("--index-parallel", type=int, default=None, help="Index build parallel degree (e.g., 8).")
    # Misc
    p.add_argument("--max-docs", type=int, default=None, help="Limit number of chunks to ingest (debug/testing).")
    p.add_argument("--dry-run", action="store_true", help="Parse/split only; do not write to DB.")
    return p.parse_args()


def connect(user: str, password: str, dsn: str):
    if not user or not password or not dsn:
        print("[ERROR] Missing DB connection info. Provide --user/--password/--dsn or ORA_USER/ORA_PASSWORD/ORA_DSN.", file=sys.stderr)
        sys.exit(2)
    conn = oracledb.connect(user=user, password=password, dsn=dsn)
    return conn


def load_docs(urls, pdfs):
    docs = []

    # URLs
    if urls:
        print(f"[INFO] Loading {len(urls)} URLs ...")
        url_loader = UnstructuredURLLoader(urls=urls, continue_on_failure=True, mode="single")
        try:
            docs.extend(url_loader.load())
        except Exception as e:
            print(f"[WARN] URL loader error: {e}")

    # PDFs
    if pdfs:
        print(f"[INFO] Loading {len(pdfs)} PDFs ...")
        for path in pdfs:
            if not os.path.exists(path):
                print(f"[WARN] PDF not found: {path}")
                continue
            loader = PyPDFLoader(path)
            pages = loader.load()

            # Title extraction
            title = os.path.basename(path)
            if fitz:
                try:
                    doc_fitz = fitz.open(path)
                    title = doc_fitz.metadata.get("title") or doc_fitz[0].get_text("text").split("\n")[0].strip() or title
                except Exception:
                    pass

            for d in pages:
                d.metadata = dict(d.metadata or {})
                d.metadata["source"] = path
                d.metadata["title"] = title

            docs.extend(pages)

    print(f"[INFO] Loaded {len(docs)} raw documents (pre-splitting).")
    return docs


def split_docs(all_docs, chunk_size, chunk_overlap):
    splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    chunks = splitter.split_documents(all_docs)
    print(f"[INFO] Split into {len(chunks)} chunks.")
    return chunks


def make_embeddings(provider: str, model_name: str, conn):
    if provider == "database":
        # default Oracle model name
        model = model_name or "ALL_MINILM_L12_V2"
        print(f"[INFO] Using OracleEmbeddings with model='{model}' in-database.")
        return OracleEmbeddings(conn=conn, params={"provider": "database", "model": model})
    else:
        # default HF model
        hf_model = model_name or "sentence-transformers/all-MiniLM-L6-v2"
        print(f"[INFO] Using HuggingFaceEmbeddings model='{hf_model}'.")
        return HuggingFaceEmbeddings(model_name=hf_model)


def distance_strategy(name: str):
    name = name.lower()
    if name == "cosine":
        return DistanceStrategy.COSINE
    if name == "dot":
        return DistanceStrategy.DOT_PRODUCT
    if name == "euclidean":
        return DistanceStrategy.EUCLIDEAN_DISTANCE
    return DistanceStrategy.COSINE


def create_index(conn, vectordb, kind: str, idx_name: str = None, accuracy: int = None, parallel: int = None):
    params = {}
    if idx_name:
        params["idx_name"] = idx_name
    params["idx_type"] = "HNSW" if kind == "hnsw" else "IVF"
    if accuracy is not None:
        params["accuracy"] = accuracy
    if parallel is not None:
        params["parallel"] = parallel

    print(f"[INFO] Creating {params['idx_type']} index with params: {params}")
    oraclevs_utils.create_index(conn, vectordb, params=params)
    print("[INFO] Index created.")


def main():
    args = parse_args()

    urls = args.urls if args.urls is not None else DEFAULT_URLS
    pdfs = args.pdfs if args.pdfs is not None else DEFAULT_PDFS

    # 1) Connect
    t0 = time.time()
    conn = connect(args.user, args.password, args.dsn)
    print("[INFO] Connected to Oracle 23ai.")

    # 2) Load + split
    raw_docs = load_docs(urls, pdfs)
    chunks = split_docs(raw_docs, args.chunk_size, args.chunk_overlap)
    if args.max_docs:
        chunks = chunks[: args.max_docs]
        print(f"[INFO] Limiting to first {len(chunks)} chunks due to --max-docs.")

    if args.dry_run:
        print("[DRY-RUN] Skipping DB write.")
        return

    # 3) Embeddings
    embedder = make_embeddings(args.provider, args.model_name, conn)

    # 4) Ingest into OracleVS
    strat = distance_strategy(args.distance)
    print(f"[INFO] Ingesting into table '{args.table_name}' with distance='{args.distance}' ...")
    vectordb = OracleVS.from_documents(
        chunks,
        embedder,
        client=conn,
        table_name=args.table_name,
        distance_strategy=strat,
    )
    print(f"[INFO] Ingest complete. Table: {args.table_name}")

    # 5) Optional index
    if args.index != "none":
        idx_name = args.index_name or (f"{args.table_name}_{args.index}_IDX")
        create_index(conn, vectordb, args.index, idx_name, args.index_accuracy, args.index_parallel)

    # 6) Quick test search
    sample_q = "How do I use OEDACLI in Exascale?"
    print(f"[INFO] Test similarity_search for: {sample_q!r}")
    res = vectordb.similarity_search(sample_q, k=3)
    for i, d in enumerate(res, 1):
        src = (d.metadata or {}).get("source", "N/A")
        print(f"\n[{i}] source={src}\n{d.page_content[:200]}...")

    print(f"\n[INFO] Done in {time.time() - t0:.1f}s.")


if __name__ == "__main__":
    main()
