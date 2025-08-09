import os, time, hmac, hashlib, sqlite3, json
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Header, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="Suna Control Plane", version="1.1.0")

DB_PATH       = os.getenv("DB_PATH", "control.db")
SHARED_SECRET = os.getenv("SHARED_SECRET", "")
GH_SECRET     = os.getenv("GITHUB_WEBHOOK_SECRET", "")

# ---------- db ----------
def db_init():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS commands(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          agent TEXT,
          action TEXT,
          payload TEXT,
          ts INTEGER,
          sig TEXT,
          executed INTEGER DEFAULT 0,
          result TEXT
        )
        """)
db_init()

def queue_command(agent: str, action: str, payload: str, ts: int, sig: str) -> int:
    with sqlite3.connect(DB_PATH) as c:
        cur = c.execute(
            "INSERT INTO commands(agent,action,payload,ts,sig,executed) VALUES(?,?,?,?,?,0)",
            (agent, action, payload, ts, sig),
        )
        c.commit()
        return cur.lastrowid

def hmac_hex(msg: str) -> str:
    return hmac.new(SHARED_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest() if SHARED_SECRET else ""

def ok(data: dict) -> JSONResponse:
    d = {"status": "ok"}
    d.update(data)
    return JSONResponse(d)

# ---------- health ----------
@app.get("/")
def root():
    return {"status": "Suna Control Plane is Live!"}

@app.get("/debug_next_sig")
def debug_next_sig(agent: str, ts: int):
    msg = f"{agent}.next..{ts}"
    sig = hmac_hex(msg)
    masked = (SHARED_SECRET[:1] + "***" + SHARED_SECRET[-2:]) if SHARED_SECRET else "(empty)"
    return {"ts": ts, "agent": agent, "message": msg, "expected_sig": sig, "secret_masked": masked}

@app.get("/debug_cmd_sig")
def debug_cmd_sig(agent: str, action: str, payload: str, ts: int):
    msg = f"{agent}.{action}.{payload}.{ts}"
    sig = hmac_hex(msg)
    masked = (SHARED_SECRET[:1] + "***" + SHARED_SECRET[-2:]) if SHARED_SECRET else "(empty)"
    return {
        "ts": ts, "agent": agent, "action": action, "payload_echo": payload,
        "message": msg, "expected_sig": sig, "secret_masked": masked
    }

# ---------- core: cmd / next / result ----------
@app.post("/cmd")
def cmd(
    agent: str = Query(...),
    action: str = Query(...),
    payload: str = Query(""),
    ts: int = Query(...),
    sig: str = Query(...)
):
    """Signature: HMAC(secret, f"{agent}.{action}.{payload}.{ts}")"""
    msg = f"{agent}.{action}.{payload}.{ts}"
    if not (SHARED_SECRET and hmac.compare_digest(hmac_hex(msg), sig)):
        raise HTTPException(401, "Invalid signature")
    job_id = queue_command(agent, action, payload, int(ts), sig)
    return ok({"queued": True, "id": job_id})

@app.get("/next")
def nxt(agent: str, ts: int, sig: str):
    """Signature: HMAC(secret, f"{agent}.next..{ts}")"""
    msg = f"{agent}.next..{ts}"
    if not (SHARED_SECRET and hmac.compare_digest(hmac_hex(msg), sig)):
        raise HTTPException(401, "Invalid signature")
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute(
            "SELECT id, action, payload FROM commands WHERE agent=? AND executed=0 ORDER BY id ASC LIMIT 1",
            (agent,)
        ).fetchone()
    if not row:
        return {"status": "no_pending"}
    return ok({"id": row[0], "action": row[1], "payload": row[2]})

@app.post("/result")
def result(
    agent: str = Query(...),
    id: int = Query(...),
    result: str = Query(""),
    ts: int = Query(...),
    sig: str = Query(...)
):
    """Signature: HMAC(secret, f"{agent}.result.{id}.{ts}")"""
    msg = f"{agent}.result.{id}.{ts}"
    if not (SHARED_SECRET and hmac.compare_digest(hmac_hex(msg), sig)):
        raise HTTPException(401, "Invalid signature")
    with sqlite3.connect(DB_PATH) as c:
        c.execute("UPDATE commands SET executed=1, result=? WHERE id=?", (result[:8000], id))
        c.commit()
    return ok({"saved": True})

# ---------- GitHub webhook → queue suna.say ----------
@app.post("/gh")
async def gh_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_event: Optional[str] = Header(default=None),
):
    if not GH_SECRET:
        raise HTTPException(500, "GITHUB_WEBHOOK_SECRET not configured")

    raw = await request.body()
    expected = "sha256=" + hmac.new(GH_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not (x_hub_signature_256 and hmac.compare_digest(expected, x_hub_signature_256)):
        raise HTTPException(401, "Invalid GitHub signature")

    body = await request.json()
    event = (x_github_event or "unknown").lower()

    def _fmt_sha(s: str) -> str: return s[:7] if s else ""
    def _summary() -> str:
        if event == "push":
            repo = body.get("repository", {}).get("full_name")
            pusher = body.get("pusher", {}).get("name")
            branch = (body.get("ref") or "").split("/")[-1]
            commit = _fmt_sha(body.get("after", ""))
            count = len(body.get("commits") or [])
            return f"🟣 PUSH • {repo}@{branch} by {pusher} • {count} commit(s) • {commit}"
        if event == "pull_request":
            repo = body.get("repository", {}).get("full_name")
            pr = body.get("number")
            action = body.get("action")
            title = (body.get("pull_request") or {}).get("title")
            user = ((body.get("pull_request") or {}).get("user") or {}).get("login")
            return f"🟣 PR {action} • {repo} #{pr} by {user} — {title}"
        if event == "workflow_run":
            repo = body.get("repository", {}).get("full_name")
            wr = body.get("workflow_run") or {}
            name = wr.get("name")
            status = wr.get("status")
            conclusion = wr.get("conclusion")
            head_branch = wr.get("head_branch")
            head_sha = _fmt_sha(wr.get("head_sha", ""))
            emoji = "✅" if conclusion == "success" else ("❌" if conclusion else "🚧")
            return f"{emoji} CI • {repo} • {name} [{status}/{conclusion}] • {head_branch}@{head_sha}"
        if event == "deployment_status":
            repo = body.get("repository", {}).get("full_name")
            ds = body.get("deployment_status") or {}
            state = ds.get("state")
            env = (body.get("deployment") or {}).get("environment")
            sha = _fmt_sha((body.get("deployment") or {}).get("sha", ""))
            emoji = {"success":"🚀","failure":"🛑","in_progress":"⏳"}.get(state, "📦")
            return f"{emoji} Deploy • {repo} • {env} • {state} • {sha}"
        return f"ℹ️ GitHub event: {event}"

    msg = _summary()
    # queue as a command for Suna to relay via Telegram
    queue_command("suna", "say", msg, int(time.time()), sig="gh")
    return ok({"queued": {"agent": "suna", "action": "say", "message": msg}})
