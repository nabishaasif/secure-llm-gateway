import re

INJECTION_PATTERNS = [
    (r"ignore (all |previous |above )?instructions", 0.9),
    (r"you are now", 0.7),
    (r"pretend (you are|to be)", 0.7),
    (r"do anything now", 0.85),
    (r"jailbreak", 0.9),
    (r"system prompt", 0.6),
    (r"reveal your (instructions|prompt|system)", 0.85),
    (r"act as (if you have no|without) (restrictions|limits)", 0.9),
    (r"forget (your|all) (rules|guidelines|training)", 0.85),
    (r"<\|.*?\|>", 0.8),
    (r"\[INST\]|\[\/INST\]", 0.75),
    (r"bypass (safety|filter|content)", 0.85),
]

def detect_injection(text: str) -> dict:
    text_lower = text.lower()
    matched = []
    highest_score = 0.0

    for pattern, score in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            matched.append({"pattern": pattern, "score": score})
            if score > highest_score:
                highest_score = score

    return {
        "injection_score": round(highest_score, 3),
        "matched_patterns": matched,
        "is_suspicious": highest_score > 0.4,
    }