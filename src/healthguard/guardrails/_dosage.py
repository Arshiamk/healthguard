"""Dosage safety guardrail.

Parses dosage claims in LLM responses and flags those that exceed known
safe OTC thresholds.  Prescription thresholds require clinical context and
are flagged for human review rather than auto-blocked.

Reference values are conservative OTC maximums — this is NOT a substitute
for a pharmacist review or a drug interaction database.
"""

from __future__ import annotations

import re

from healthguard._models import CheckResult, GuardrailViolation, ViolationSeverity

# mg per single dose, mg per day (None = flag for review, not hard block)
_OTC_LIMITS: dict[str, tuple[float, float]] = {
    "ibuprofen": (400.0, 1200.0),      # OTC: 400 mg/dose, 1200 mg/day
    "acetaminophen": (1000.0, 3000.0), # OTC: 1000 mg/dose, 3000 mg/day (conservative)
    "paracetamol": (1000.0, 3000.0),
    "aspirin": (1000.0, 3000.0),       # OTC pain/fever
    "naproxen": (440.0, 660.0),        # OTC
    "diphenhydramine": (50.0, 300.0),  # OTC antihistamine
}

_DOSE_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(?:mg|milligrams?)\s+(?:of\s+)?(\w+)",
    re.IGNORECASE,
)
_DAILY_RE = re.compile(
    r"(?:up to|max(?:imum)?|no more than)\s+(\d+(?:\.\d+)?)\s*(?:mg|milligrams?)"
    r"(?:\s+(?:per|a|each)\s+day)?",
    re.IGNORECASE,
)


class DosageGuardrail:
    """Inspect an LLM response for unsafe dosage claims."""

    def check(self, response: str) -> CheckResult:
        violations: list[GuardrailViolation] = []

        # Check single-dose mentions
        for match in _DOSE_RE.finditer(response):
            amount = float(match.group(1))
            drug = match.group(2).lower()
            if drug in _OTC_LIMITS:
                single_limit, _ = _OTC_LIMITS[drug]
                if amount > single_limit:
                    violations.append(
                        GuardrailViolation(
                            rule_id="DOSE-001",
                            severity=ViolationSeverity.HIGH,
                            message=(
                                f"Single dose of {amount:.0f}mg {drug} exceeds the "
                                f"OTC maximum of {single_limit:.0f}mg."
                            ),
                            evidence=match.group(0),
                            remediation=(
                                f"Recommend {single_limit:.0f}mg or advise the user "
                                "to consult a pharmacist for higher doses."
                            ),
                        )
                    )

        # Check stated daily totals
        for match in _DAILY_RE.finditer(response):
            amount = float(match.group(1))
            # Try to find an associated drug nearby (within 100 chars)
            start = max(0, match.start() - 100)
            context = response[start : match.end()].lower()
            for drug, (_, daily_limit) in _OTC_LIMITS.items():
                if drug in context and amount > daily_limit:
                    violations.append(
                        GuardrailViolation(
                            rule_id="DOSE-002",
                            severity=ViolationSeverity.HIGH,
                            message=(
                                f"Stated daily total of {amount:.0f}mg {drug} exceeds "
                                f"the OTC daily maximum of {daily_limit:.0f}mg."
                            ),
                            evidence=match.group(0),
                            remediation=(
                                f"Recommend no more than {daily_limit:.0f}mg per day "
                                "for OTC use, or advise consultation with a clinician."
                            ),
                        )
                    )

        return CheckResult(
            safe=len(violations) == 0,
            violations=violations,
            blocked=any(
                v.severity == ViolationSeverity.CRITICAL for v in violations
            ),
        )
