from __future__ import annotations
import json, logging, os, time
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from .reasoning import analyze, _mock_reasoning, runtime_status
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
app = FastAPI(title="Jev Reasoning Engine", version="4.0.0")
@app.get("/health")
async def health():
    runtime = runtime_status(); mode = runtime.get("mode")
    return {"status": "degraded" if mode in {"fallback", "unavailable"} else "ok",
            "service": "jev-client", "reasoning": runtime}
class AnalyzeRequest(BaseModel):
    finding: str
    evidence: list[str]
    context: Optional[str] = None
@app.post("/analyze")
async def analyze_endpoint(payload: AnalyzeRequest): return analyze(payload.model_dump())
class ChatMessage(BaseModel):
    role: str
    content: str
class ChatCompletionRequest(BaseModel):
    model: Optional[str] = None
    max_tokens: Optional[int] = None
    messages: list[ChatMessage]
@app.post("/v1/chat/completions")
async def chat_completions(payload: ChatCompletionRequest):
    user_message = next((m.content for m in reversed(payload.messages) if m.role == "user"), "{}")
    try: evidence_obj = json.loads(user_message)
    except json.JSONDecodeError: evidence_obj = {"finding": user_message, "evidence": [], "context": None}
    result = _mock_reasoning(evidence_obj)
    return {"id": f"chatcmpl-mock-{int(time.time())}", "object": "chat.completion", "model": payload.model or "jev-local-mock",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps(result)}, "finish_reason": "stop"}]}
