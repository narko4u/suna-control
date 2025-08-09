from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import sqlite3, hmac, hashlib, os, time, logging

app = FastAPI()
DB_PATH = "control.db"
SECRET  = os.getenv("SHARED_SECRET", "VS-Genesis-777")
AGENTS  = {"suna"}

logger = logging.getLogger("uvicorn")

def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent TEXT, action TEXT, payload TEXT,
            ts INTEGER, sig TEXT,
            executed INTEGER DEFAULT 0, result TEXT
        )""")
init_db()

def ok(data): return JSONResponse({"status":"ok", **data})

def verify(agent, action, payload, ts, sig):
    if agent not in AGENTS:
        return False
    try:
        ts = int(ts)
    except:
        return False
    # 5-minute clock skew
    if abs(time.time() - ts) > 300:
        return False
    # ---- SIGNING FORMAT (DOUBLE DOT FOR EMPTY PAYLOAD) ----
    # message = f"{agent}.{action}.{payload}.{ts}"   # used when payload is present
    if payload == "":
        message = f"{agent}.{action}..{ts}"          # empty payload => two dots
    else:
        message = f"{agent}.{action}.{payload}.{ts}"
    mac = hmac.new(SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig)

@app.get("/")
def root():
    return {"status":"Suna Control Plane is Live!"}

# ------------------ DEBUG ENDPOINT ------------------
@app.get("/debug_next_sig")
def debug_next_sig(agent: str = "suna", ts: int = 0):
    """Return how the server builds/signs the /next request."""
    if not ts:
        ts = int(time.time())
    msg = f"{agent}.next..{ts}"
    sig = hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    masked = SECRET if len(SECRET) <= 6 else (SECRET[:3] + "***" + SECRET[-3:])
    logger.info(f"/debug_next_sig ts={ts} msg='{msg}' sig_prefix={sig[:12]}")
    return {
        "ts": ts,
        "agent": agent,
        "message": msg,
        "expected_sig": sig,
        "secret_masked": masked
    }

@app.post("/cmd")
def cmd(data: dict):
    agent   = data.get("agent","")
    action  = data.get("action","")
    payload = data.get("payload","")
    ts      = data.get("ts",0)
    sig     = data.get("sig","")
    if not verify(agent, action, payload, ts, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")
    with sqlite3.connect(DB_PATH) as c:
        c.execute("INSERT INTO commands (agent, action, payload, ts, sig) VALUES (?,?,?,?,?)",
                  (agent, action, payload, int(ts), sig))
    return ok({"queued": True})

@app.get("/next")
def nxt(agent: str, ts: int, sig: str):
    # signature is over f"{agent}.next..{ts}" (empty payload)
    if not verify(agent, "next", "", ts, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute(
            "SELECT id, action, payload FROM commands WHERE agent=? AND executed=0 ORDER BY id ASC LIMIT 1",
            (agent,)
        ).fetchone()
    if not row:
        return {"status":"no_pending"}
    return ok({"id":row[0], "action":row[1], "payload":row[2]})

@app.post("/result")
def result(data: dict):
    cmd_id = data.get("id")
    res    = (data.get("result","") or "")[:8000]
    if not cmd_id:
        raise HTTPException(status_code=400, detail="Missing id")
    with sqlite3.connect(DB_PATH) as c:
        c.execute("UPDATE commands SET executed=1, result=? WHERE id=?", (res, cmd_id))
    return ok({"saved": True})
