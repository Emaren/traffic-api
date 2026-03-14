from fastapi import FastAPI

app = FastAPI(title="Traffic API")

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.get("/api/summary")
async def summary():
    return {
        "ok": True,
        "projects": [],
        "hosts": [],
        "totals": {},
    }
