# metrics_utils.py
import os, json, time, threading
from datetime import datetime, timezone
from collections import defaultdict

_LOG_LOCK = threading.Lock()

def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)

def append_jsonl(path: str, obj: dict):
    """Thread-safe append to a JSONL file."""
    _ensure_dir(path)
    line = json.dumps(obj, ensure_ascii=False)
    with _LOG_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def aggregate_counts(path: str, period: str = "day"):
    """
    Aggregate counts by tool and day/week from a JSONL metrics file.
    Returns dict like: {"by_day": {...}, "by_week": {...}} (subset depending on 'period').
    """
    if not os.path.isfile(path):
        return {}
    by_day  = defaultdict(lambda: defaultdict(int))   # {YYYY-MM-DD: {tool: count}}
    by_week = defaultdict(lambda: defaultdict(int))   # {YYYY-WW: {tool: count}}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except Exception:
                continue
            tool = ev.get("tool") or ev.get("method") or "unknown"
            ts   = ev.get("ts") or ev.get("time") or utc_iso()
            try:
                dt = datetime.fromisoformat(ts.replace("Z","+00:00"))
            except Exception:
                continue
            day_key  = dt.strftime("%Y-%m-%d")
            week_key = dt.strftime("%Y-%U")
            by_day[day_key][tool]   += 1
            by_week[week_key][tool] += 1

    if period == "day":
        return {"by_day": by_day}
    elif period == "week":
        return {"by_week": by_week}
    return {"by_day": by_day, "by_week": by_week}

# --- feedback utils ---
def feedback_blocks(text: str, voted: str | None, payload_json: str) -> list[dict]:
    """
    Build blocks for a message with optional 'You voted …' note.
    voted: "up" | "down" | None
    """
    note = ""
    if voted == "up":   note = "_You voted: :thumbsup:, thanks for your feedback!_"
    if voted == "down": note = "_You voted: :thumbsdown:, thanks for your feedback!_"

    header_section = {
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*How do you like the answer?*"}
    }

    actions = {
        "type": "actions",
        "elements": [
            {
                "type": "button", "text": {"type": "plain_text", "text": "👍"},
                "action_id": "fb_up", "value": payload_json
            },
            {
                "type": "button", "text": {"type": "plain_text", "text": "👎"},
                "action_id": "fb_down", "value": payload_json
            },
        ],
    }

    out = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    if voted:  # show note and remove buttons once voted
        out.append({"type": "context", "elements": [{"type": "mrkdwn", "text": note}]})
    else:
        out.append(header_section)
        out.append(actions)
    return out

def record_feedback_click(body: dict, vote: str, client):
    # unpack payload
    try:
        action = (body.get("actions") or [])[0]
        payload = json.loads(action.get("value") or "{}")
    except Exception:
        payload = {}

    msg = body.get("message", {}) or {}
    container = body.get("container", {}) or {}

    channel_id = (
        container.get("channel_id")
        or (body.get("channel") or {}).get("id")
        or msg.get("channel")
        or (msg.get("channel") or {}).get("id")
    )
    ts = container.get("message_ts") or msg.get("ts")
    user_id = (body.get("user") or {}).get("id") or "unknown"

    # simple de-dupe (uuid,user)
    try:
        SEEN = record_feedback_click._seen  # type: ignore[attr-defined]
    except Exception:
        SEEN = record_feedback_click._seen = set()  # type: ignore[attr-defined]
    vote_key = (payload.get("uuid"), user_id)
    first_vote = vote_key not in SEEN
    SEEN.add(vote_key)

    if first_vote:
        append_jsonl(os.getenv("FEEDBACK_PATH", "./metrics/feedback.jsonl"), {
            "ts": utc_iso(),
            "slack_channel": channel_id,
            "slack_msg_ts": ts,
            "user": user_id,
            "vote": vote,
            "context": payload.get("context", {}),
            "uuid": payload.get("uuid"),
            "raw_callback": {"type": body.get("type")},
        })

    # --- IMPORTANT: prefer block text over fallback text
    original_text = None
    blocks = msg.get("blocks") or []
    for b in blocks:
        if b.get("type") == "section":
            t = (b.get("text") or {}).get("text")
            if t:
                original_text = t
                break
    if not original_text:
        # fallback if blocks missing in payload
        original_text = msg.get("text") or " "

    try:
        client.chat_update(
            channel=channel_id,
            ts=ts,
            # keep fallback short; real content is in blocks
            text="Answer with feedback controls",
            blocks=feedback_blocks(original_text, voted=vote, payload_json=json.dumps(payload)),
        )
    except Exception as e:
        append_jsonl(os.getenv("FEEDBACK_PATH", "./metrics/feedback.jsonl"), {
            "ts": utc_iso(),
            "type": "update_error",
            "error": str(e),
            "channel": channel_id,
            "ts_msg": ts,
            "uuid": payload.get("uuid"),
        })
