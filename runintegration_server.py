#!/usr/bin/env python3
"""
MCP server for RunIntegration utilities.

Exposes three tools:
- idle_envs() -> {"idle_envs": list|str}
- disabled_envs() -> {"disabled_envs": list}
- status(rack: str) -> {"status": str}

Depends on your existing runintegration_agent.py in PYTHONPATH.
"""

import os
import json
import re
from typing import Any, Dict, List, Union

# pip install mcp
from mcp.server.fastmcp import FastMCP

from runintegration_agent import (
    get_idle_envs_concurrent,
    get_disabled_envs,
    check_runintegration_status,
)

# Optional: assert required files exist early (fail-fast & clearer errors)
RUNTABLE_PATH = "/net/10.32.19.91/export/exadata_images/ImageTests/daily_runs_1/OSS_MAIN/runtable"
CONNECT_FILE = "/net/10.32.19.91/export/exadata_images/ImageTests/.pxeqa_connect"

app = FastMCP("runintegration-mcp")

@app.tool()
def idle_envs(max_workers: int | None = None, ssh_timeout: int | None = None, per_host_limit: int | None = None):
    """
    List idle RunIntegration environments (fast concurrent scanner).
    Optional args:
      max_workers: overall concurrency (default 24)
      ssh_timeout: per-SSH connect timeout seconds (default 3)
      per_host_limit: cap concurrent checks per user@host (default None)
    """
    mw = max_workers or 24
    st = ssh_timeout or 3
    ph = per_host_limit
    result = get_idle_envs_concurrent(max_workers=mw, ssh_timeout=st, per_host_limit=ph)
    return {"idle_envs": result}

@app.tool()
def disabled_envs() -> Dict[str, List[str]]:
    """
    List disabled environments from runtable.

    Returns:
      {"disabled_envs": ["<FULL_RACK> : <DEPLOY_TYPE>", ...]}
    """
    result = get_disabled_envs() or []
    return {"disabled_envs": result}

def _normalize_rack(r: str) -> str:
    m = re.search(r'(sca[\w-]*?adm\d{2})', r, flags=re.IGNORECASE)
    return m.group(1) if m else r.strip()

@app.tool()
def status(rack: str) -> Dict[str, str]:
    """
    Get RunIntegration status for a given rack (e.g., 'scaqan07adm07').

    Args:
      rack: short rack name to search in runtable.

    Returns:
      {"status": "<human-readable status string>"}
    """
    if not isinstance(rack, str) or not rack.strip():
        return {"status": "Invalid 'rack' parameter."}
    base = _normalize_rack(rack)
    return {"status": check_runintegration_status(rack.strip())}

@app.tool()
def tool_manifest() -> Dict[str, Any]:
    return {
        "service": "runintegration-mcp",
        "tools": [
            {
                "name": "idle_envs",
                "description": "List idle environments in RunIntegration pool.",
                "intents": ["idle envs", "available envs", "free envs"],
                "patterns": [r"\bidle\b.*runintegration", r"\bavailable\b.*runintegration", r"\bfree\b.*runintegration", r"\bavailable\b.*runintegration"]
            },
            {
                "name": "disabled_envs",
                "description": "List disabled environments in RunIntegration pool.",
                "intents": ["disabled envs", "unavailable envs"],
                "patterns": [r"\bdisabled\b.*runintegration", r"\bunavailable\b.*runintegration"]
            },
            {
                "name": "status",
                "description": "Show RunIntegration job status for a rack (e.g., scaqap19adm01).",
                "intents": ["status", "what job", "running", "busy"],
                "patterns": [r"\b(what\s+job|status|running|busy)\b.*sca.*adm\d{2}"]
            }
        ]
    }


if __name__ == "__main__":
    # Starts an MCP stdio server (reads/writes JSON-RPC on stdin/stdout)
    app.run()
