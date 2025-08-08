from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import sqlite3, hmac, hashlib, os, time

app = FastAPI()
DB_PATH = "control.db"
SECRET  = os.getenv("SHARED_SECRET", "VS-Genesis-777")
AGENTS  = {"suna"}

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
    if agent not in AGENTS: return False
    try: ts = int(ts)
    except: return False
    if abs(time.time()-ts) > 300: return False
    mac = hmac.new(SECRET.encode(), f"{agent}.{action}.{payload}.{ts}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig)

@app.get("/")
def root():
    return {"status":"Suna Control Plane is Live!"}

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
    # signature expected over f"{agent}.next..{ts}"
    if not verify(agent, "next", "", ts, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT id, action, payload FROM commands WHERE agent=? AND executed=0 ORDER BY id ASC LIMIT 1",
                        (agent,)).fetchone()
    if not row: return {"status":"no_pending"}
    return ok({"id":row[0], "action":row[1], "payload":row[2]})

@app.post("/result")
def result(data: dict):
    cmd_id = data.get("id")
    res    = (data.get("result","") or "")[:8000]
    if not cmd_id: raise HTTPException(status_code=400, detail="Missing id")
    with sqlite3.connect(DB_PATH) as c:
        c.execute("UPDATE commands SET executed=1, result=? WHERE id=?", (res, cmd_id))
    return ok({"saved": True})
