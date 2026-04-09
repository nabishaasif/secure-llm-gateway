def apply_policy(injection_result: dict,
                 pii_result: dict,
                 config: dict) -> dict:

    block_threshold = config["injection_detection"]["block_threshold"]
    default_action  = config["policy"]["default_action"]
    injection_score = injection_result["injection_score"]

    # Rule 1: Block on high injection score
    if injection_score >= block_threshold:
        return {
            "decision": "BLOCK",
            "reason": f"Injection score {injection_score} exceeds threshold {block_threshold}",
            "safe_text": None,
        }

    # Rule 2 & 3: PII handling
    if pii_result["has_pii"]:
        if default_action == "block":
            return {
                "decision": "BLOCK",
                "reason": f"PII detected: {[e['type'] for e in pii_result['entities_found']]}",
                "safe_text": None,
            }
        elif default_action == "mask":
            return {
                "decision": "MASK",
                "reason": f"PII masked: {[e['type'] for e in pii_result['entities_found']]}",
                "safe_text": pii_result["anonymized_text"],
            }

    # Rule 4: Allow
    return {
        "decision": "ALLOW",
        "reason": "No threats detected",
        "safe_text": pii_result.get("anonymized_text") or "N/A",
    }