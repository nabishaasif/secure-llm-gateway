import yaml
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from gateway.injection_detector import detect_injection
from gateway.pii_analyzer import build_analyzer, analyze_pii
from gateway.policy_engine import apply_policy
from gateway.latency import LatencyTracker

with open("config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

print("Loading Presidio analyzer... please wait")
ANALYZER = build_analyzer()
print("Analyzer ready!")

app = FastAPI(
    title="Secure LLM Gateway",
    description="Security gateway for LLM applications - CSC 262 Lab Mid",
    version="1.0.0",
)

class UserInput(BaseModel):
    text: str

@app.post("/analyze")
def analyze(input: UserInput):
    tracker = LatencyTracker()
    tracker.start()

    injection_result = detect_injection(input.text)
    tracker.mark("injection_detection")

    pii_result = analyze_pii(
        text=input.text,
        analyzer=ANALYZER,
        threshold=CONFIG["presidio"]["score_threshold"],
    )
    tracker.mark("pii_analysis")

    policy_result = apply_policy(injection_result, pii_result, CONFIG)
    tracker.mark("policy_decision")

    latency = tracker.summary()

    return {
        "decision": policy_result["decision"],
        "reason": policy_result["reason"],
        "safe_text": policy_result["safe_text"],
        "injection_score": injection_result["injection_score"],
        "matched_patterns": injection_result["matched_patterns"],
        "pii_entities": pii_result["entities_found"],
        "composite_flags": pii_result["composite_flags"],
        "latency": latency,
    }

@app.get("/")
def root():
    return {"status": "Gateway is running", "docs": "/docs"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)