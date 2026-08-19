"""
HealthGuard — Clinical AI Guardrails SDK.

Drop-in safety layer for LLMs used in healthcare: PHI redaction,
hallucination detection, policy enforcement, and immutable audit trails.

Quick start::

    from healthguard import HealthGuard

    hg = HealthGuard()

    # Redact PHI before it reaches the model
    safe_prompt = hg.redact("Patient John Smith, DOB 1980-03-15, has hypertension")
    # → "Patient [NAME], DOB [DATE], has hypertension"

    # Validate a model response for clinical safety
    result = hg.check_response(
        response="Take 500mg of ibuprofen every 4 hours, up to 3000mg per day.",
        context={"query_type": "dosage"},
    )
    print(result.safe)        # False — exceeds OTC daily limit
    print(result.violations)  # [DosageViolation(...)]
"""

from healthguard._core import HealthGuard
from healthguard._models import (
    AuditEntry,
    CheckResult,
    GuardrailViolation,
    RedactionResult,
    ViolationSeverity,
)
from healthguard._policy import Policy, PolicyAction, PolicyRule
from healthguard._version import __version__

__all__ = [
    "HealthGuard",
    "Policy",
    "PolicyRule",
    "PolicyAction",
    "CheckResult",
    "RedactionResult",
    "GuardrailViolation",
    "ViolationSeverity",
    "AuditEntry",
    "__version__",
]
