from fastapi import FastAPI
from pydantic import BaseModel, Field
import asyncio
from concurrent.futures import ThreadPoolExecutor

from threat_c_dga.predict import predict_domain
from threat_d_ja4.predict import predict_session

app = FastAPI(
    title="DeepSentinel AI Engine",
    description="Enterprise-grade threat detection engine with stateful jitter tracking & IDN protection",
    version="4.0.0"
)

executor = ThreadPoolExecutor(max_workers=4)

class DomainQuery(BaseModel):
    domain: str = Field(..., min_length=4, max_length=253)

class SessionQuery(BaseModel):
    bytes_in: float = Field(..., ge=0)
    bytes_out: float = Field(..., ge=0)
    duration_ms: float = Field(..., gt=0)
    packet_count: int = Field(..., ge=1)
    ja4_fingerprint: str = Field(..., min_length=10, max_length=64)
    inter_arrival_variance: float = Field(10.0, ge=0.0, description="Rolling variance of packet timing to detect C2 sleep jitter")

@app.get("/")
def health_check():
    return {"status": "online", "engine": "DeepSentinel AI Engine v4.0 (Flawless Architecture)"}

@app.post("/analyze/domain")
async def analyze_domain(query: DomainQuery):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, predict_domain, query.domain)
    return {"engine": "Threat c (ONNX 253-Char Sequence + Entropy)", "result": result}

@app.post("/analyze/session")
async def analyze_session(query: SessionQuery):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor, 
        predict_session, 
        query.bytes_in, query.bytes_out, query.duration_ms, query.packet_count, query.ja4_fingerprint, query.inter_arrival_variance
    )
    return {"engine": "Threat d (XGBoost Jitter Analysis + SHAP XAI)", "result": result}