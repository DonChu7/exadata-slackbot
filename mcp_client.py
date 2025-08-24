#!/usr/bin/env python3
# Persistent MCP client with auto-reconnect watchdog
# Requires: pip install -U mcp fastmcp anyio

import os, sys
import asyncio, json, threading, time, atexit
from typing import Any, Dict, List, Optional, Tuple, Callable

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from metrics_utils import append_jsonl, utc_iso
import traceback

METRICS_CALLS_PATH = os.getenv("METRICS_CALLS_PATH", "./metrics/mcp_calls.jsonl")
FEEDBACK_PATH = os.getenv("FEEDBACK_PATH", "./metrics/feedback.jsonl")

class PersistentMCPClient:
    """
    - Keeps one background lifecycle task that owns the MCP stdio context.
    - Auto-reconnects if the server exits/crashes.
    - Serializes tool calls.
    - Retries a call once if it fails due to a dropped connection.
    """

    def __init__(
        self,
        server_cmd: List[str],
        max_backoff: float = 10.0,
        health_interval: float = 30.0,   # periodically check list_tools
    ):
        self._server_cmd = list(server_cmd)
        self._server_cmd_str = " ".join(server_cmd)  # for metrics
        self._params = StdioServerParameters(command=server_cmd[0], args=server_cmd[1:], env=None)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._ready_evt = threading.Event()          # set when connected
        self._stop_evt: Optional[asyncio.Event] = None
        self._reconnect_evt: Optional[asyncio.Event] = None

        self._session: Optional[ClientSession] = None
        self._tools: List[str] = []
        self._lock: Optional[asyncio.Lock] = None     # serialize JSON-RPC
        self._task: Optional[asyncio.Future] = None

        self._max_backoff = max_backoff
        self._health_interval = health_interval

        self._thread.start()
        # start watchdog lifecycle on the bg loop
        self._task = asyncio.run_coroutine_threadsafe(self._watchdog_lifecycle(), self._loop)
        # wait for first connection (or keep going if you prefer lazy)
        self._ready_evt.wait(timeout=15)
        atexit.register(self.close)
    
    #--------- log event ---------
    def _log_call(self, tool: str, args: Dict[str, Any], ok: bool, *, error: str | None = None,
                retry: bool = False, duration_ms: int | None = None, context: dict | None = None):
        try:
            append_jsonl(METRICS_CALLS_PATH, {
                "ts": utc_iso(),
                "tool": tool,
                "args_keys": sorted(list((args or {}).keys())),
                "server_cmd": self._server_cmd_str,
                "ok": bool(ok),
                "retry": bool(retry),
                "error": error[:400] if error else None,
                "duration_ms": duration_ms,
                "context": context or {},
            })
        except Exception:
            # never let metrics writing crash the client
            pass

    # ---------- event loop plumbing ----------
    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    # ---------- core connect once ----------
    async def _connect_once(self) -> bool:
        """Open stdio + session; return True on success, False on fail."""
        try:
            # enter async contexts here and remember them to exit later
            self._stdio_ctx = stdio_client(self._params)
            read, write = await self._stdio_ctx.__aenter__()
            self._session_ctx = ClientSession(read, write)
            self._session = await self._session_ctx.__aenter__()
            await self._session.initialize()

            # cache tools + create lock
            tools = await self._session.list_tools()
            self._tools = [t.name for t in tools.tools]
            self._lock = asyncio.Lock()
            self._ready_evt.set()
            return True
        except Exception:
            # cleanup partial contexts if needed
            try:
                if getattr(self, "_session_ctx", None):
                    await self._session_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            try:
                if getattr(self, "_stdio_ctx", None):
                    await self._stdio_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            self._session = None
            self._lock = None
            self._tools = []
            self._ready_evt.clear()
            return False

    # ---------- graceful close of current session ----------
    async def _close_once(self):
        try:
            if getattr(self, "_session_ctx", None):
                await self._session_ctx.__aexit__(None, None, None)
        finally:
            if getattr(self, "_stdio_ctx", None):
                await self._stdio_ctx.__aexit__(None, None, None)
        self._session = None
        self._lock = None
        self._tools = []
        self._ready_evt.clear()

    # ---------- watchdog lifecycle ----------
    async def _watchdog_lifecycle(self):
        self._stop_evt = asyncio.Event()
        self._reconnect_evt = asyncio.Event()

        backoff = 0.5
        connected_once = False

        while not self._stop_evt.is_set():
            ok = await self._connect_once()
            if not ok:
                # exponential backoff before retry
                await asyncio.sleep(backoff)
                backoff = min(self._max_backoff, backoff * 2)
                continue

            # connected
            connected_once = True
            backoff = 0.5

            # run a health loop until stop/reconnect needed
            try:
                while not (self._stop_evt.is_set() or self._reconnect_evt.is_set()):
                    # periodic health check
                    await asyncio.sleep(self._health_interval)
                    try:
                        tools = await self._session.list_tools()
                        self._tools = [t.name for t in tools.tools]
                    except Exception:
                        # session seems bad; trigger reconnect
                        self._reconnect_evt.set()
                        break
            finally:
                # close session
                try:
                    await self._close_once()
                except Exception:
                    pass

            if self._stop_evt.is_set():
                break
            # clear and retry connect
            self._reconnect_evt.clear()

        # end loop

    def close(self):
        if not (self._thread.is_alive() and self._stop_evt):
            return
        # signal stop on loop
        def _signal():
            self._stop_evt.set()
        self._loop.call_soon_threadsafe(_signal)
        if self._task:
            try:
                self._task.result(timeout=3)
            except Exception:
                pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=3)

    # ---------- public calls ----------
    def _ensure_ready(self, timeout: float = 15.0):
        if not self._ready_evt.wait(timeout=timeout):
            raise RuntimeError("MCP server not ready (connect timeout).")

    def _call_with_retry(self, fn: Callable[[], Any]):
        """Run a call; if it fails due to connection, trigger reconnect and retry once."""
        try:
            return fn(), False
        except Exception as e:
            # trigger reconnect and wait for ready again
            def _signal():
                if self._reconnect_evt:
                    self._reconnect_evt.set()
            self._loop.call_soon_threadsafe(_signal)
            self._ensure_ready(timeout=20.0)
            return fn(),True


    def call_tool(self, name: str, args: Dict[str, Any], *, metrics_context: dict | None = None):
        self._ensure_ready()
        start = time.perf_counter()

        def _rpc():
            async def _run():
                async with self._lock:
                    if name not in self._tools:
                        tools = await self._session.list_tools()
                        self._tools = [t.name for t in tools.tools]
                        if name not in self._tools:
                            raise RuntimeError(f"Tool '{name}' not found. Available: {self._tools}")
                    result = await self._session.call_tool(name, args or {})
                # parse into a dict
                for part in (result.content or []):
                    if getattr(part, "type", "") == "text" and hasattr(part, "text"):
                        try:
                            return json.loads(part.text)
                        except Exception:
                            return {"raw_text": part.text}
                return {"content": [getattr(c, "dict", lambda: c.__dict__)() for c in (result.content or [])]}
            return self._run_coro(_run())

        try:
            (res, retried) = self._call_with_retry(_rpc)
            dur = int((time.perf_counter() - start) * 1000)
            ok = "error" not in (res or {})
            self._log_call(name, args, ok=ok, retry=retried, duration_ms=dur,
                           error=None if ok else (json.dumps(res)[:400] if res else "unknown error"),
                           context=metrics_context,
                           )
            return res
        except Exception as e:
            dur = int((time.perf_counter() - start) * 1000)
            err = f"{type(e).__name__}: {e}\n{traceback.format_exc()[:800]}"
            self._log_call(name, args, ok=False, retry=True, duration_ms=dur, error=err)
            raise

    # convenience
    def idle_envs(self):     return self.call_tool("idle_envs", {})
    def disabled_envs(self): return self.call_tool("disabled_envs", {})
    def status(self, rack: str): return self.call_tool("status", {"rack": rack})


# ---- CLI quick test ----
if __name__ == "__main__":
    client = PersistentMCPClient(["python", "runintegration_server.py"])
    try:
        if len(sys.argv) < 2:
            print("Usage:\n  python mcp_client.py idle\n  python mcp_client.py disabled\n  python mcp_client.py status <rack>")
            sys.exit(0)
        cmd = sys.argv[1].lower()
        if cmd == "idle":
            print(json.dumps(client.idle_envs(), indent=2, ensure_ascii=False))
        elif cmd == "disabled":
            print(json.dumps(client.disabled_envs(), indent=2, ensure_ascii=False))
        elif cmd == "status":
            if len(sys.argv) < 3:
                print("Usage: python mcp_client.py status <rack>")
                sys.exit(1)
            print(json.dumps(client.status(sys.argv[2]), indent=2, ensure_ascii=False))
        else:
            print(f"Unknown action: {cmd}")
    finally:
        client.close()
