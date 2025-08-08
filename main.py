from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import sqlite3
import hmac
import hashlib
import os
import time

app = FastAPI()

DB_PATH = "control.db"
SECRET = os.getenv("SHARED_SECRET", "VS-Genesis-777")
AGENTS = ["suna", "nova", "dpk"]

# init db
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS commands (
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
init_db()

def verify_sig(agent, action, payload, ts, sig):
    if agent not in AGENTS:
        return False
    try:
        ts_i = int(ts)
    except Exception:
        return False
    if abs(time.time() - ts_i) > 300:
        return False
    msg = f"{agent}.{action}.{payload}.{ts}"
    mac = hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig)

@app.post("/cmd")
async def add_cmd(data: dict):
    agent = data.get("agent")
    action = data.get("action")
    payload = data.get("payload")
    ts = data.get("ts")
    sig = data.get("sig")
    if not verify_sig(agent, action, payload, ts, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO commands (agent, action, payload, ts, sig) VALUES (?, ?, ?, ?, ?)",
            (agent, action, payload, ts, sig)
        )
    return {"status": "OK", "queued": True}

@app.get("/next")
async def get_next(agent: str, ts: int, sig: str):
    # Senti signs: f"{agent}.next..{ts}"
    if not verify_sig(agent, "next", "", ts, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, action, payload FROM commands WHERE agent=? AND executed=0 ORDER BY id ASC LIMIT 1",
            (agent,)
        ).fetchone()
    if not row:
        return {"status": "no_pending"}
    return {"status": "ok", "id": row[0], "action": row[1], "payload": row[2]}

@app.post("/result")
async def post_result(data: dict):
    cmd_id = data.get("id")
    result = data.get("result", "")[:8000]
    if not cmd_id:
        raise HTTPException(status_code=400, detail="Missing id")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE commands SET executed=1, result=? WHERE id=?",
            (result, cmd_id)
        )
    return {"status": "result_saved"}
