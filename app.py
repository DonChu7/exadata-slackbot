# app.py — slim Slack bot wired to MCP tools

import os as OS
import re
import json
import time
import base64
import tempfile as TF
import threading
import subprocess
import requests
from urllib.parse import quote, urlparse, urljoin

from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from mcp_client import PersistentMCPClient
from router import Router

import uuid
from metrics_utils import feedback_blocks, record_feedback_click, append_jsonl, utc_iso

# ---------------------------------------------------------------------------
# Boot / env
# ---------------------------------------------------------------------------
load_dotenv()

SLACK_BOT_TOKEN = OS.getenv("SLACK_BOT_TOKEN", "")
SLACK_APP_TOKEN = OS.getenv("SLACK_APP_TOKEN", "")
FEEDBACK_PATH = OS.getenv("FEEDBACK_PATH", "./metrics/feedback.jsonl")

JENKINS_URL        = OS.getenv("JENKINS_URL", "https://ci-cloud.us.oracle.com/jenkins/escs-test")
JENKINS_USER       = OS.getenv("JENKINS_USER", "jiahao.l.li@oracle.com")
JENKINS_API_TOKEN  = OS.getenv("JENKINS_API_TOKEN", "")
JENKINS_FOLDER     = OS.getenv("JENKINS_FOLDER", "UPGRADE_LOOP_RUN")
JENKINS_JOB        = OS.getenv("JENKINS_JOB", "01_PRE_SETUP_FOR_SM")
JENKINS_VERIFY_SSL = OS.getenv("JENKINS_VERIFY_SSL", "true").lower() == "true"

# MCP servers (commands to launch each tool server)
RUNINTEG_CMD = OS.getenv("RUNINTEG_CMD",     "python /scratch/dongyzhu/exadata-slackbot/runintegration_server.py").split()
OEDA_CMD     = OS.getenv("OEDA_CMD",         "python /scratch/dongyzhu/exadata-slackbot/oeda_server.py").split()
RAG_CMD      = OS.getenv("RAG_CMD",          "python /scratch/dongyzhu/exadata-slackbot/exa23ai_rag_server.py").split()
SUM_CMD      = OS.getenv("SUM_CMD",          "python /scratch/dongyzhu/exadata-slackbot/summarizer_server.py").split()
GENAI4TEST_CMD = OS.getenv("GENAI4TEST_CMD", "python /scratch/dongyzhu/exadata-slackbot/genai4test_server.py").split()

# Default genoedaxml path (allowlisted in oeda_server)
DEFAULT_GENXML = OS.getenv("GENOEDAXML_PATH",
    "/net/dbdevfssmnt-shared01.dev3fss1phx.databasede3phx.oraclevcn.com/exadata_dev_image_oeda/genoeda/genoedaxml"
)

# ---------------------------------------------------------------------------
# feedbacks 
# ---------------------------------------------------------------------------
def _chunk_text(s: str, limit: int = 2800) -> list[str]:
    """Split s into ~limit-sized chunks on paragraph/line boundaries."""
    if len(s) <= limit:
        return [s]
    parts, cur = [], []
    cur_len = 0
    for para in s.split("\n\n"):
        block = (para + "\n\n")
        if cur_len + len(block) > limit and cur:
            parts.append("".join(cur).rstrip())
            cur, cur_len = [], 0
        if len(block) > limit:
            # fallback: split long paragraph by lines
            for line in block.splitlines(keepends=True):
                if cur_len + len(line) > limit and cur:
                    parts.append("".join(cur).rstrip())
                    cur, cur_len = [], 0
                if len(line) > limit:
                    # last‑resort: hard chunk long line
                    for i in range(0, len(line), limit):
                        parts.append(line[i:i+limit])
                    continue
                cur.append(line); cur_len += len(line)
        else:
            cur.append(block); cur_len += len(block)
    if cur:
        parts.append("".join(cur).rstrip())
    return parts or [s]


# --- app.py ---

def _chunk_text(s: str, limit: int = 2800) -> list[str]:
    if len(s) <= limit:
        return [s]
    parts, cur, cur_len = [], [], 0
    for para in s.split("\n\n"):
        block = para + "\n\n"
        if cur_len + len(block) > limit and cur:
            parts.append("".join(cur).rstrip())
            cur, cur_len = [], 0
        if len(block) > limit:
            for line in block.splitlines(keepends=True):
                if cur_len + len(line) > limit and cur:
                    parts.append("".join(cur).rstrip())
                    cur, cur_len = [], 0
                while len(line) > limit:
                    parts.append(line[:limit]); line = line[limit:]
                cur.append(line); cur_len += len(line)
        else:
            cur.append(block); cur_len += len(block)
    if cur:
        parts.append("".join(cur).rstrip())
    return parts or [s]

def post_text_chunks(app, channel_id: str, thread_ts: str | None, text: str) -> str:
    """Post long text as multiple plain messages. Returns ts of the first post."""
    chunks = _chunk_text(text, limit=2800)
    first_ts = None
    for i, c in enumerate(chunks):
        res = app.client.chat_postMessage(
            channel=channel_id, thread_ts=thread_ts if i == 0 else first_ts, text=c
        )
        if first_ts is None:
            first_ts = res["ts"]
    return first_ts or thread_ts

def post_feedback_tail(app, channel_id: str, thread_ts: str | None, *,
                       text_for_record: str, context: dict | None = None) -> str:
    """
    Append a tiny trailing message with 👍👎 buttons.
    Stores the full 'text_for_record' to feedback.jsonl, but shows only a short label in Slack.
    """
    uid = str(uuid.uuid4())
    record = {"uuid": uid, "ts": utc_iso(), "context": context or {}, "original_text": text_for_record}
    append_jsonl(FEEDBACK_PATH, record)
    tiny_payload = json.dumps({"uuid": uid})

    res = app.client.chat_postMessage(
        channel=channel_id,
        thread_ts=thread_ts,
        text="Rate this answer",
        blocks=feedback_blocks("Rate this answer", voted=None, payload_json=tiny_payload),
    )
    return res["ts"]


# ---------------------------------------------------------------------------
# Helpers (Jenkins + file transfer)
# ---------------------------------------------------------------------------
def _jenkins_session():
    if not (JENKINS_URL and JENKINS_USER and JENKINS_API_TOKEN):
        raise RuntimeError("Missing JENKINS_URL/JENKINS_USER/JENKINS_API_TOKEN")
    s = requests.Session()
    s.trust_env = False
    s.auth = (JENKINS_USER, JENKINS_API_TOKEN)
    s.verify = JENKINS_VERIFY_SSL
    try:
        r = s.get(f"{JENKINS_URL}/crumbIssuer/api/json", timeout=10)
        if r.ok:
            j = r.json()
            s.headers[j.get("crumbRequestField", "Jenkins-Crumb")] = j.get("crumb")
    except Exception:
        pass
    return s

def trigger_upgrade_loop_run(params=None):
    s = _jenkins_session()
    base = f"{JENKINS_URL}/job/{JENKINS_FOLDER}/job/{JENKINS_JOB}"
    endpoint = f"{base}/buildWithParameters" if params else f"{base}/build"
    resp = s.post(endpoint, data=(params or {}), timeout=20)
    if resp.status_code not in (200, 201, 202, 302):
        raise RuntimeError(f"Jenkins returned {resp.status_code}: {resp.text[:300]}")
    return {"queued": True, "queue_url": resp.headers.get("Location"), "job_url": base}

def _fmt_duration(ms: int) -> str:
    s = int(ms) // 1000 if ms else 0
    h, m, sec = s // 3600, (s % 3600)//60, s % 60
    return f"{h}h {m}m {sec}s" if h else (f"{m}m {sec}s" if m else f"{sec}s")

def _resolve_build_url_from_queue(queue_url: str, session) -> str:
    if not queue_url: return ""
    url = queue_url.rstrip("/") + "/api/json"
    for _ in range(300):
        try:
            r = session.get(url, timeout=15)
            if r.ok:
                data = r.json()
                if data.get("cancelled"):
                    return ""
                exe = data.get("executable") or {}
                burl = (exe.get("url") or "").rstrip("/")
                if burl:
                    return burl
        except Exception:
            pass
        time.sleep(5)
    return ""

def _monitor_and_notify(queue_url: str, base_job_url: str, channel_id: str, thread_ts: str):
    try:
        s = _jenkins_session()
    except Exception as e:
        try:
            app.client.chat_postMessage(channel=channel_id, thread_ts=thread_ts,
                                        text=f"Unable to monitor Jenkins build: {e}")
        except Exception:
            pass
        return

    build_url = _resolve_build_url_from_queue(queue_url, s)
    if not build_url and base_job_url:
        try:
            r = s.get(f"{base_job_url}/lastBuild/api/json", timeout=15)
            if r.ok:
                u = (r.json().get("url") or "").rstrip("/")
                build_url = u or build_url
        except Exception:
            pass
    if not build_url:
        try:
            app.client.chat_postMessage(channel=channel_id, thread_ts=thread_ts,
                                        text="Unable to resolve build URL for monitoring.")
        except Exception:
            pass
        return

    # poll until complete
    api = build_url.rstrip("/") + "/api/json"
    last_result = None
    for _ in range(360):
        try:
            r = s.get(api, timeout=20)
            if r.ok:
                j = r.json()
                building = j.get("building", False)
                result = j.get("result")
                if not building and result:
                    dur = _fmt_duration(j.get("duration", 0))
                    final = f"Job finished: {result}\nBuild: {build_url}\nDuration: {dur}"
                    app.client.chat_postMessage(channel=channel_id, thread_ts=thread_ts, text=final)
                    return
                last_result = result
        except Exception:
            pass
        time.sleep(10)
    app.client.chat_postMessage(
        channel=channel_id, thread_ts=thread_ts,
        text=f"Monitoring timed out. Latest known status: {last_result or 'BUILDING'}\nBuild: {build_url}"
    )

def _parse_env_params_from_text(text: str):
    t = (text or "").lower()
    if re.search(r"\br1x\b", t): return {"ENV": "r1x"}
    if re.search(r"\br1\b",  t): return {"ENV": "r1"}
    return None

def scp_file_with_key(file_path: str, destination: str, ssh_key_path: str) -> bool:
    try:
        cmd = ["scp", "-i", ssh_key_path, file_path, destination]
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print("[ERROR] SCP failed:", e.stderr.decode())
        return False

# ---------------------------------------------------------------------------
# Slack app
# ---------------------------------------------------------------------------
app = App(token=SLACK_BOT_TOKEN)

# MCP clients (persistent stdio)
RUNINTEG_CLIENT = PersistentMCPClient(RUNINTEG_CMD)
OEDA_CLIENT     = PersistentMCPClient(OEDA_CMD)
RAG_CLIENT      = PersistentMCPClient(RAG_CMD)
SUM_CLIENT      = PersistentMCPClient(SUM_CMD)
GENAI4TEST_CLIENT = PersistentMCPClient(GENAI4TEST_CMD)

router = Router()
MANIFESTS = []
for client in (RUNINTEG_CLIENT, OEDA_CLIENT, RAG_CLIENT, SUM_CLIENT, GENAI4TEST_CLIENT):
    try:
        m = client.call_tool("tool_manifest", {})
        if isinstance(m, dict): MANIFESTS.append(m)
    except Exception:
        pass
router.load_from_manifests(MANIFESTS)

print("[ROUTER] loaded services:")
for m in MANIFESTS:
    svc = m.get("service")
    tools = [t.get("name") for t in m.get("tools", [])]
    print(f"  - {svc}: {tools}")

# Optional: map service -> client for dispatch
SERVICE_CLIENT = {
    "oeda-mcp": OEDA_CLIENT,
    "runintegration-mcp": RUNINTEG_CLIENT,
    "oracle23ai-rag-mcp": RAG_CLIENT,
    "summarizer-mcp": SUM_CLIENT,
    "genai4test-mcp": GENAI4TEST_CLIENT,
}

def _args_for_tool(tool: str, cleaned_text: str) -> dict:
    low = cleaned_text.lower()
    if tool == "generate_oedaxml":
        # use everything after the keyword if present; else full msg
        req = cleaned_text.split("generate oedaxml", 1)[1].strip() if "generate oedaxml" in low else cleaned_text
        return {"request": req, "genoedaxml_path": DEFAULT_GENXML, "return_xml": True, "force_mock": True}
    if tool == "status":
        m = re.search(r'(sca[\w-]*?adm\d{2})', low)
        return {"rack": m.group(1)} if m else {"rack": ""}
    if tool == "idle_envs":
        return {}
    if tool == "disabled_envs":
        return {}
    if tool == "rag_query":
        return {"question": cleaned_text, "k": 3}
    if tool in ("lc_summarize_pdf_b64", "summarize_pdf_b64"):
        # router should not call this directly (needs bytes) — handled earlier
        return {}
    if tool == "lc_summarize_text":
        after = low.split("summarize", 1)[1].strip() if "summarize" in low else cleaned_text
        return {"text": after}
    # lc_summarize_pdf_b64 is built where you already download the file bytes
    if tool == "run_bug_test":
        m = re.search(r'\b(?:bug\s*#?\s*)?(\d{6,})\b', low)
        bug_no = m.group(1) if m else ""
        email = OS.getenv("GENAI4TEST_EMAIL", "dongyang.zhu@oracle.com")
        agent = OS.getenv("GENAI4TEST_AGENT", "bug_agent")
        return {"bug_no": bug_no, "email": email, "agent": agent}
    return {}


# ---------------------------------------------------------------------------
# Slack event handler
# ---------------------------------------------------------------------------
@app.action("fb_up")
def handle_fb_up(ack, body, client, say):
    ack()
    record_feedback_click(body, "up", client)

@app.action("fb_down")
def handle_fb_down(ack, body, client, say):
    ack()
    record_feedback_click(body, "down", client)

@app.event("app_mention")
def handle_app_mention(event, say, client):
    user_question = event.get("text", "")
    cleaned = " ".join(tok for tok in user_question.split() if not tok.startswith("<@"))
    lower   = cleaned.lower()
    channel_id = event["channel"]
    thread_ts  = event.get("ts")

    if "summarize" in lower:
        try:
            files = event.get("files") or []
            had_pdf = False
            for f in files:
                name = f.get("name","document.pdf"); mt = f.get("mimetype","")
                if name.lower().endswith(".pdf") or mt in ("application/pdf","application/octet-stream"):
                    had_pdf = True
                    say(f":page_facing_up: Got `{name}` — summarizing…", thread_ts=thread_ts)
                    headers = {"Authorization": f"Bearer {OS.getenv('SLACK_BOT_TOKEN','')}"}
                    r = requests.get(f["url_private_download"], headers=headers, timeout=60); r.raise_for_status()

                    with TF.NamedTemporaryFile(delete=False, suffix=f"_{name}") as tmp:
                        tmp.write(r.content)
                        tmp_path = tmp.name

                    # Call LC file-based tool (no huge b64 in MCP messages)
                    res = SUM_CLIENT.call_tool("lc_summarize_pdf_file", {"path": tmp_path})

                    # Cleanup temp file
                    try: OS.unlink(tmp_path)
                    except Exception: pass

                    # Accept both LC and manual keys
                    if res.get("error"):
                        say(f":x: Summarizer error: {res['error']}", thread_ts=thread_ts)
                    else:
                        pages = res.get("pages") or res.get("num_pages")
                        notes  = res.get("notes","") or res.get("chain_type","")
                        summary = res.get("summary")
                        if not summary:
                            say(":warning: Summarizer returned no summary.", thread_ts=thread_ts)
                        else:
                            say(f"*Summary for* `{name}` ({pages if pages is not None else '?'} pages):\n{summary}", thread_ts=thread_ts)
                            if notes: say(f"_Note_: {notes}", thread_ts=thread_ts)
            if had_pdf:
                return
        except Exception as e:
            say(f":x: MCP error (summarizer): {e}", thread_ts=thread_ts)
            return

    # --- New: router pass (metadata-driven) ---
    route = router.rule_route(cleaned)

    # Fallback: ask each MCP if it recognizes the intent (safety net)
    if not route:
        for svc_name, cli in SERVICE_CLIENT.items():
            try:
                resp = cli.call_tool("classify_intent", {"text": cleaned})
                append_jsonl(OS.getenv("METRICS_CALLS_PATH","./metrics/mcp_calls.jsonl"), {
                "ts": utc_iso(), "event": "classify_probe",
                "service": svc_name, "response": resp,
                })
                print(f"[ROUTER] classify_probe {svc_name}: {resp}")
                if isinstance(resp, dict) and resp.get("matched") and resp.get("confidence", 0) >= 0.85:
                    route = {
                        "service": resp.get("service", svc_name),
                        "tool": resp.get("tool"),
                        "score": resp.get("confidence"),
                        "rule_id": "mcp:classify_intent",
                        "slots": resp.get("slots") or {},
                    }
                    break
            except Exception:
                print(f"[ROUTER] classify_probe {svc_name} error: {e}")
                append_jsonl(OS.getenv("METRICS_CALLS_PATH","./metrics/mcp_calls.jsonl"), {
                    "ts": utc_iso(), "event": "classify_probe_error",
                    "service": svc_name, "error": str(e),
                })

    append_jsonl(OS.getenv("METRICS_CALLS_PATH","./metrics/mcp_calls.jsonl"), {
        "ts": utc_iso(),
        "event": "route_decision",
        "message": cleaned[:300],
        "route": route or {},
        })
    print(f"[ROUTER] decision for '{cleaned[:120]}...': {route}")

    if route:
        svc = route["service"] 
        tool = route["tool"]
        client_for = SERVICE_CLIENT.get(svc)
        # SAFE subset for logging
        route_ctx = {
            "router": {
                "service": svc,
                "tool": tool,
                "rule_id": route.get("rule_id"),
                "score": route.get("score"),
            },
            "slack_channel": channel_id,
            "thread_ts": thread_ts,
            # optionally:
            "user_question": cleaned[:300],
        }
        if client_for:
            try:
                # Special-case: summarize with PDFs — handled later where you already upload bytes.
                if tool == "lc_summarize_pdf_b64" and event.get("files"):
                    pass  # let your existing PDF path run
                else:
                    args = _args_for_tool(tool, cleaned)
                    res  = client_for.call_tool(tool, args, metrics_context=route_ctx)

                    # minimal display per tool (reuse your existing display blocks)
                    if tool == "generate_oedaxml":
                        status = res.get("live_mig_check")
                        prod   = res.get("ilom_product_name") or "N/A"
                        reason = res.get("live_mig_reason") or ""

                        if status == "fail":
                            say(f":no_entry: {reason}\nILOM product_name: `{prod}`", thread_ts=thread_ts)
                            return
                        elif status == "unknown" and res.get("live_migration"):
                            say(f":information_source: {reason}\nILOM product_name: `{prod}`", thread_ts=thread_ts)

                        minconfig = res.get("minconfig_json", {})
                        es_path   = res.get("es_xml_path")
                        err       = res.get("error")
                        es_err    = res.get("es_error")  

                        msg = "*Generated `minconfig.json`:*\n```" + json.dumps(minconfig, indent=2) + "```"
                        if es_path: msg += f"\n\n*XML output path:* `{es_path}`"
                        if err:     msg += f"\n\n:warning: *OEDA error:* {err}"
                        if not es_path and es_err: msg += f"\n\n:x: *genOEDA XML failed:* `{es_err}`"
                        post_with_feedback(app, channel_id, thread_ts, msg,
                            context={"feature":"oeda","tool":tool,"args":{"has_xml":bool(es_path)}}
                        )
                        # upload inline xml if present (same as you have)
                        es_b64 = res.get("es_xml_b64")
                        if es_b64:
                            xml_bytes = base64.b64decode(es_b64)
                            with TF.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
                                tmp.write(xml_bytes); tmp_path = tmp.name
                            client.files_upload_v2(
                                channels=[channel_id], thread_ts=thread_ts,
                                initial_comment="Attached is your generated `config.xml` file:",
                                file=tmp_path, filename="es.xml", title="es.xml",
                            )
                            OS.unlink(tmp_path)
                        if es_path:
                            say(f"Please run following command to deploy your hardware with the generated xml: \n"
                                f"1. `cd oss/test/tsage/sosd` \n"
                                f"2. `run doimageoeda.sh -xml [your/xml/path] -error_report -skip_ahf -remote -skip_qinq_checks_cell`",
                                    thread_ts=thread_ts)

                    elif tool == "status":
                        post_with_feedback(app, channel_id, thread_ts, res.get("status","[No status]"),
                            context={"feature":"runintegration","tool":"status"})

                    elif tool == "idle_envs":
                        idle = res.get("idle_envs", [])
                        if not idle:
                            say("😢 No idle environments found.", thread_ts=thread_ts)
                        elif isinstance(idle, list):
                            if idle and isinstance(idle[0], dict):
                                lines = [f"• `{e.get('rack_name','?')}` : {e.get('deploy_type','?')}" for e in idle]
                            else:
                                lines = [f"• `{e}`" for e in idle]
                            msg = "*🟢 Idle environments:*\n" + "\n".join(lines)
                            post_with_feedback(app, channel_id, thread_ts, msg,
                                context={"feature":"runintegration","tool":"idle_envs"})
                        else:
                            say(f":warning: Unexpected idle envs format: {type(idle).__name__}", thread_ts=thread_ts)

                    elif tool == "disabled_envs":
                        items = res.get("disabled_envs", [])
                        if not items:
                            say("No disabled environments found.", thread_ts=thread_ts)
                        else:
                            msg = "*Disabled RunIntegration envs:*\n" + "\n".join(f"• `{e}`" for e in items)
                            post_with_feedback(app, channel_id, thread_ts, msg,
                                context={"feature":"runintegration","tool":"disabled_envs"})

                    elif tool == "rag_query":
                        ans  = res.get("answer","[no answer]")
                        srcs = res.get("sources", []) or []
                        src_lines = "\n".join(f"• {s.get('title','untitled')} ({s.get('source') or 'n/a'})" for s in srcs)
                        post_with_feedback(app, channel_id, thread_ts, f"{ans}\n\n*Sources:*\n{src_lines or '—'}",
                            context={"feature":"rag","tool":"rag_query"})

                    elif tool == "lc_summarize_text":
                        post_with_feedback(app, channel_id, thread_ts, f"*Summary:*\n{res.get('summary','[no summary]')}",
                            context={"feature":"summarizer","tool":"lc_summarize_text"})
                    elif tool == "run_bug_test":
                        if not res.get("ok"):
                            say(f":x: genai4test error: {res.get('error')} (url: {res.get('request_url')})", thread_ts=thread_ts)
                            return

                        bug_no = (_args_for_tool(tool, cleaned).get("bug_no") if '_args_for_tool' in globals() else None) or "bug"
                        pieces_for_record = []  # accumulate for feedback logging

                        # 1) Summary (plain posts, chunked)
                        if res.get("summary"):
                            ts0 = post_text_chunks(
                                app, channel_id, thread_ts,
                                f"*Summary for bug {bug_no}:*\n{res['summary']}"
                            )
                            pieces_for_record.append(res["summary"])
                        else:
                            ts0 = thread_ts

                        # 2) SQL / test script (always print and attach if present)
                        sql = res.get("sql")
                        if sql:
                            pieces_for_record.append(f"[script length={len(sql)}]")
                            # Post a code block in-thread (chunked post already used above for summary)
                            preview = sql if len(sql) <= 2400 else (sql[:2400] + "\n-- [truncated]")
                            app.client.chat_postMessage(
                                channel=channel_id,
                                thread_ts=ts0,
                                text=f"*Generated Test Script ({bug_no}.sql):*\n```{preview}```",
                            )

                            # Always attach as a file too (so users can download/forward it)
                            try:
                                with TF.NamedTemporaryFile(delete=False, suffix=f"_{bug_no}.sql") as tmp:
                                    tmp.write(sql.encode("utf-8", errors="ignore"))
                                    tmp_path = tmp.name
                                app.client.files_upload_v2(
                                    channels=[channel_id],
                                    thread_ts=ts0,
                                    initial_comment="Full script attached:",
                                    file=tmp_path,
                                    filename=f"{bug_no}.sql",
                                    title=f"{bug_no}.sql",
                                )
                            finally:
                                try: OS.unlink(tmp_path)
                                except Exception: pass
                        else:
                            app.client.chat_postMessage(
                                channel=channel_id,
                                thread_ts=ts0,
                                text=":warning: The test-generation service returned no script payload.",
                            )

                        # 4) One feedback widget at the end (unchanged)
                        post_feedback_tail(
                            app, channel_id, ts0,
                            text_for_record="\n\n".join(pieces_for_record) or "(no content)",
                            context={"feature":"genai4test","tool":"run_bug_test","bug": bug_no}
                        )
                    return
            except Exception as e:
                say(f":x: Router dispatch error: {e}", thread_ts=thread_ts)
                # fall through to your legacy branches as a safety net

    # --- Jenkins trigger ---
    if ("jenkins" in lower and ("upgrade loop run" in lower or "upgrade_loop_run" in lower) and
        any(x in lower for x in ["submit", "build", "kick", "start"])):
        try:
            params = _parse_env_params_from_text(lower)
            say(text="Got it ✅ submitting Jenkins build: UPGRADE_LOOP_RUN / 01_PRE_SETUP_FOR_SM", thread_ts=thread_ts)
            result = trigger_upgrade_loop_run(params=params)
            msg = "\n".join(filter(None, [
                f"Params: {params}" if params else "",
                f"Queue: {result.get('queue_url')}",
                f"Job: {result.get('job_url')}",
            ]))
            say(text=msg, thread_ts=thread_ts)
            threading.Thread(
                target=_monitor_and_notify, args=(result.get("queue_url"), result.get("job_url"), channel_id, thread_ts),
                daemon=True
            ).start()
        except Exception as e:
            say(text=f"Trigger failed: `{e}`", thread_ts=thread_ts)
        return

    # --- File transfer (scp) ---
    if any(w in lower for w in ["send", "transfer", "upload"]) and any(w in lower for w in ["file", "attachment"]):
        match = re.search(r'\b[\w.-]+@[\d.]+:[\w/\-_.]+', user_question)
        if not event.get("files"):
            say("⚠️ You asked me to send a file, but no attachment was found.", thread_ts=thread_ts); return
        if not match:
            say("❌ Please include a destination like `user@host:/path`.", thread_ts=thread_ts); return
        dest = match.group()
        try:
            for f in event["files"]:
                name = f["name"]; url = f["url_private_download"]
                headers = {"Authorization": f"Bearer {OS.getenv('SLACK_BOT_TOKEN','')}"}
                r = requests.get(url, headers=headers); r.raise_for_status()
                with TF.NamedTemporaryFile(delete=False, suffix=f"_{name}") as tmp:
                    tmp.write(r.content); tmp_path = tmp.name
                if scp_file_with_key(tmp_path, dest, ssh_key_path="/net/10.32.19.91/export/exadata_images/ImageTests/.pxeqa_connect"):
                    say(f"✅ Sent `{name}` to `{dest}`", thread_ts=thread_ts)
                else:
                    say(f"❌ Failed to send `{name}` to `{dest}`", thread_ts=thread_ts)
                OS.unlink(tmp_path)
        except Exception as e:
            say(f"⚠️ Error sending file: {e}", thread_ts=thread_ts)
        return

    # --- OEDA (MCP) ---
    if ("generate oedaxml" in lower) or ("generate xml" in lower):
        try:
            req = cleaned.split("generate oedaxml", 1)[1].strip()
            payload = {
                "request": req,
                "genoedaxml_path": DEFAULT_GENXML,
                "return_xml": True,
                "force_mock": True,
            }

            res = OEDA_CLIENT.call_tool("generate_oedaxml", payload)
            # Check hardware support for live migration
            if res.get("live_mig_check") == "fail":  # <-- you can set this flag in your genoedaxml agent
                rack_desc = res.get("rack_desc", "N/A")
                say((":no_entry: Live migration requires X10 or newer hardware.\n"
                    f"Detected rackDescription: `{rack_desc}`"), thread_ts=thread_ts)
                return
            minconfig = res.get("minconfig_json", {})
            es_path   = res.get("es_xml_path")
            es_b64    = res.get("es_xml_b64")
            err       = res.get("error")

            msg = "*Generated `minconfig.json`:*\n```" + json.dumps(minconfig, indent=2) + "```"
            if es_path: msg += f"\n\n*XML output path:* `{es_path}`"
            if err:     msg += f"\n\n:warning: *OEDA error:* {err}"
            post_with_feedback(
                app, channel_id, thread_ts, msg,
                context={"feature": "oeda", "tool": "generate_oedaxml", "args": {"has_xml": bool(es_path)}}
            )

            if es_b64:
                xml_bytes = base64.b64decode(es_b64)
                with TF.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
                    tmp.write(xml_bytes); tmp_path = tmp.name
                client.files_upload_v2(
                    channels=[channel_id], thread_ts=thread_ts,
                    initial_comment="Here is your generated `config.xml` file:",
                    file=tmp_path, filename="es.xml", title="es.xml",
                )
                OS.unlink(tmp_path)
        except Exception as e:
            say(f"❌ MCP error (OEDA): {e}", thread_ts=thread_ts)
        return

    # --- RunIntegration (MCP): rack status ---
    if re.search(r'\b(what\s+job|status|running|busy)\b', lower) and re.search(r'\bsca[\w-]*?adm\d{2}\b', lower):
        m = re.search(r'(sca[\w-]*?adm\d{2})', lower)
        rack_short = m.group(1) if m else None
        if not rack_short:
            say("No rack info found in your message.", thread_ts=thread_ts); return
        try:
            result = RUNINTEG_CLIENT.status(rack_short)
            post_with_feedback(
                app, channel_id, thread_ts, result.get("status", "[No status found]"),
                context={"feature": "runintegration", "tool": "status", "rack": rack_short}
            )
        except Exception as e:
            say(f":x: MCP error (status): {e}", thread_ts=thread_ts)
        return

    # --- RunIntegration (MCP): disabled envs ---
    if re.search(r'\b(disabled|unavailable)\b.*runintegration', lower) or re.search(r'what.*envs.*disabled.*runintegration', lower):
        try:
            res = RUNINTEG_CLIENT.disabled_envs()
            items = res.get("disabled_envs", [])
            if not items:
                say("No disabled environments found.", thread_ts=thread_ts)
            else:
                msg = "*Disabled RunIntegration envs:*\n" + "\n".join(f"• `{e}`" for e in items)
                post_with_feedback(
                    app, channel_id, thread_ts, msg,
                    context={"feature": "runintegration", "tool": "disabled_envs"}
                )
        except Exception as e:
            say(f":x: MCP error (disabled_envs): {e}", thread_ts=thread_ts)
        return

    # --- RunIntegration (MCP): idle envs ---
    if re.search(r'\b(idle|available|free)\b.*runintegration', lower) or re.search(r'which.*envs.*submit.*runintegration', lower):
        try:
            res = RUNINTEG_CLIENT.idle_envs()
            idle = res.get("idle_envs", [])
            if not idle:
                say("😢 No idle environments found.", thread_ts=thread_ts)
            elif isinstance(idle, str):
                say(idle, thread_ts=thread_ts)
            elif isinstance(idle, list):
                if idle and isinstance(idle[0], dict):
                    msg = "*🟢 Idle environments (RunIntegration):*\n" + "\n".join(
                        f"• `{e.get('rack_name','?')}` : {e.get('deploy_type','?')}" for e in idle
                    )
                    post_with_feedback(
                    app, channel_id, thread_ts, msg,
                    context={"feature": "runintegration", "tool": "idle_envs"}
                    )
                else:
                    msg = "*🟢 Idle environments:*\n" + "\n".join(f"• `{e}`" for e in idle)
                    post_with_feedback(
                        app, channel_id, thread_ts, msg,
                        context={"feature": "runintegration", "tool": "idle_envs"}
                    )
            else:
                say(f":warning: Unexpected idle envs format: {type(idle).__name__}", thread_ts=thread_ts)
        except Exception as e:
            say(f":x: MCP error (idle_envs): {e}", thread_ts=thread_ts)
        return

    # --- Summarize (MCP) ---
    # (this stays late, after router)
    if "summarize" in lower:
        try:
            after = cleaned.split("summarize", 1)[1].strip() if "summarize" in lower else ""
            if after:
                res = SUM_CLIENT.call_tool("lc_summarize_text", {"text": after})
                if res.get("error"):
                    say(f":x: Summarizer error: {res['error']}", thread_ts=thread_ts)
                else:
                    say(f"*Summary:*\n{res.get('summary','[no summary]')}", thread_ts=thread_ts)
            else:
                say("Attach a PDF and say “summarize”, or say “summarize <text>”.", thread_ts=thread_ts)
            return
        except Exception as e:
            say(f":x: MCP error (summarizer): {e}", thread_ts=thread_ts)
            return

    # --- Oracle 23ai RAG (MCP) — default fallback ---
    try:
        res = RAG_CLIENT.call_tool("rag_query", {"question": cleaned, "k": 3})
        if "error" in res:
            say(f":x: RAG error: {res['error']}", thread_ts=thread_ts); return
        ans = res.get("answer", "[no answer]")
        srcs = res.get("sources", [])
        src_lines = "\n".join(f"• {s.get('title','untitled')} ({s.get('source') or 'n/a'})" for s in srcs)
        say(f"{ans}\n\n*Sources:*\n{src_lines or '—'}", thread_ts=thread_ts)
    except Exception as e:
        say(f":x: MCP error (RAG): {e}", thread_ts=thread_ts)

    


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("[BOOT] Starting Slack bot...")
    try:
        handler = SocketModeHandler(app, SLACK_APP_TOKEN)
        handler.start()
    finally:
        # graceful MCP shutdown
        for cli in (RUNINTEG_CLIENT, OEDA_CLIENT, RAG_CLIENT, SUM_CLIENT, GENAI4TEST_CLIENT):
            try: cli.close()
            except Exception: pass
