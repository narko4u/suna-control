import os, hmac, hashlib, time
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="Suna Control Plane", version="1.0.0")

SHARED_SECRET = os.getenv("SHARED_SECRET", "")

def hmac_hex(msg: str) -> str:
    if not SHARED_SECRET:
        return ""  # makes it obvious we forgot to set the var
    return hmac.new(SHARED_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()

@app.get("/")
def root():
    return {"status": "Suna Control Plane is Live!"}

# -------------------------
# Core endpoints
# -------------------------

@app.post("/cmd")
def cmd(agent: str, action: str, payload: str, ts: int, sig: str):
    """
    Signature format for /cmd:
      message = "{agent}.{action}.{payload}.{ts}"
      sig = sha256_hmac(SHARED_SECRET, message)
    """
    message = f"{agent}.{action}.{payload}.{ts}"
    expected = hmac_hex(message)
    if not expected or sig != expected:
        raise HTTPException(status_code=401, detail="Invalid signature")
    # TODO: enqueue work for Suna (for now just echo)
    return {"accepted": True, "echo": {"agent": agent, "action": action, "payload": payload, "ts": ts}}

@app.get("/next")
def next_(agent: str, ts: int, sig: str):
    """
    Signature format for /next:
      message = "{agent}.next..{ts}"   # NOTE the double dot between 'next' and TS
      sig = sha256_hmac(SHARED_SECRET, message)
    """
    message = f"{agent}.next..{ts}"
    expected = hmac_hex(message)
    if not expected or sig != expected:
        raise HTTPException(status_code=401, detail="Invalid signature")
    # No real queue yet – return empty
    return {"ok": True, "agent": agent, "items": []}

@app.post("/result")
def result(agent: str, task_id: str, result: str, ts: int, sig: str):
    """
    Signature format for /result:
      message = "{agent}.result.{task_id}.{ts}"
    """
    message = f"{agent}.result.{task_id}.{ts}"
    expected = hmac_hex(message)
    if not expected or sig != expected:
        raise HTTPException(status_code=401, detail="Invalid signature")
    return {"ok": True}

# -------------------------
# Debug endpoints (read‑only)
# -------------------------

@app.get("/debug_next_sig")
def debug_next_sig(agent: str, ts: int):
    message = f"{agent}.next..{ts}"
    sig = hmac_hex(message)
    return {
        "ts": ts,
        "agent": agent,
        "message": message,
        "expected_sig": sig,
        "secret_masked": f"\n{SHARED_SECRET[:1]}***{SHARED_SECRET[-2:]}\n" if SHARED_SECRET else "(empty)"
    }

@app.get("/debug_cmd_sig")
def debug_cmd_sig(agent: str, action: str, payload: str, ts: int):
    message = f"{agent}.{action}.{payload}.{ts}"
    sig = hmac_hex(message)
    return {
        "ts": ts,
        "agent": agent,
        "action": action,
        "payload_echo": payload,
        "message": message,
        "expected_sig": sig,
        "secret_masked": f"\n{SHARED_SECRET[:1]}***{SHARED_SECRET[-2:]}\n" if SHARED_SECRET else "(empty)"
    }
