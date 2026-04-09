import re
from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

class ApiKeyRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern("API_KEY_SK",      r"\bsk-[a-zA-Z0-9]{20,}\b",            0.85),
        Pattern("API_KEY_BEARER",  r"\bBearer\s+[a-zA-Z0-9\-_\.]{20,}\b", 0.80),
        Pattern("API_KEY_GENERIC", r"\b[a-zA-Z0-9]{32,40}\b",             0.50),
    ]
    def __init__(self):
        super().__init__(
            supported_entity="API_KEY",
            patterns=self.PATTERNS,
            context=["key", "token", "secret", "api", "auth"],
        )
class InternalIdRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern("EMPLOYEE_ID", r"\bEMP-\d{4,6}\b", 0.90),
        Pattern("ORDER_ID",    r"\bORD-\d{5,8}\b", 0.90),
        Pattern("TICKET_ID",   r"\bTKT-\d{4,6}\b", 0.85),
    ]
    def __init__(self):
        super().__init__(
            supported_entity="INTERNAL_ID",
            patterns=self.PATTERNS,
            context=["employee", "order", "ticket", "id", "reference"],
        )    
class ContextAwarePhoneRecognizer(PatternRecognizer):
    """
    Phone recognizer with manual context boosting.
    Does NOT pass context to parent to avoid Presidio internal conflict.
    """
    PATTERNS = [
        Pattern("PHONE_INTL",  r"\+?[0-9]{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", 0.6),
        Pattern("PHONE_LOCAL", r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", 0.5),
    ]
    CONTEXT_WORDS = ["call", "contact", "reach", "phone", "mobile", "dial", "number"]

    def __init__(self):
        # No context passed to parent — we handle boosting manually
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
        )

    def analyze(self, text, entities, nlp_artifacts=None):
        results = super().analyze(text, entities, nlp_artifacts)
        boosted = []
        text_lower = text.lower()
        for result in results:
            boost = 0.0
            for word in self.CONTEXT_WORDS:
                if word in text_lower:
                    boost = 0.15
                    break
            boosted_score = min(result.score + boost, 1.0)
            boosted.append(
                RecognizerResult(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    score=boosted_score,
                )
            )
        return boosted

def detect_composite_pii(text: str, results: list) -> list:
    entity_types = {r.entity_type for r in results}
    composite_flags = []

    if "PERSON" in entity_types and "EMAIL_ADDRESS" in entity_types:
        composite_flags.append({
            "type": "COMPOSITE_IDENTITY",
            "description": "Name + Email detected together - high risk",
            "risk": "HIGH",
        })

    if "PERSON" in entity_types and "PHONE_NUMBER" in entity_types:
        composite_flags.append({
            "type": "COMPOSITE_CONTACT",
            "description": "Name + Phone detected together",
            "risk": "MEDIUM",
        })

    return composite_flags

def build_analyzer() -> AnalyzerEngine:
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
    })
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

    analyzer.registry.add_recognizer(ApiKeyRecognizer())
    analyzer.registry.add_recognizer(InternalIdRecognizer())
    analyzer.registry.add_recognizer(ContextAwarePhoneRecognizer())
    return analyzer

def analyze_pii(text: str, analyzer: AnalyzerEngine, threshold: float = 0.6) -> dict:
    anonymizer = AnonymizerEngine()

    results = analyzer.analyze(
        text=text,
        language="en",
        score_threshold=threshold,
    )

    calibrated = [r for r in results if r.score >= threshold]
    composite_flags = detect_composite_pii(text, calibrated)
    anonymized = anonymizer.anonymize(text=text, analyzer_results=calibrated)

    return {
        "entities_found": [
            {
                "type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": round(r.score, 3),
                "value": text[r.start:r.end],
            }
            for r in calibrated
        ],
        "composite_flags": composite_flags,
        "anonymized_text": anonymized.text,
        "has_pii": len(calibrated) > 0,
    }
