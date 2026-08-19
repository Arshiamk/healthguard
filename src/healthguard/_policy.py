"""Policy engine: define rules that block or flag certain query types."""

from __future__ import annotations

import re
from collections.abc import Callable
from enum import StrEnum

from pydantic import BaseModel, Field

from healthguard._models import CheckResult, GuardrailViolation, ViolationSeverity


class PolicyAction(StrEnum):
    """What to do when a rule matches."""

    BLOCK = "block"
    FLAG = "flag"
    LOG = "log"


class PolicyRule(BaseModel):
    """A single named policy rule."""

    id: str
    description: str
    action: PolicyAction = PolicyAction.FLAG
    severity: ViolationSeverity = ViolationSeverity.HIGH
    # Pattern matched against the raw text (prompt or response).
    pattern: str | None = None
    # Optional callable for complex logic. Receives text, returns bool (True = match).
    matcher: Callable[[str], bool] | None = Field(default=None, exclude=True)

    model_config = {"arbitrary_types_allowed": True}

    def matches(self, text: str) -> bool:
        if self.matcher is not None:
            return self.matcher(text)
        if self.pattern is not None:
            return bool(re.search(self.pattern, text, re.IGNORECASE))
        return False


class Policy(BaseModel):
    """A named collection of policy rules applied as a unit."""

    name: str
    description: str = ""
    rules: list[PolicyRule] = Field(default_factory=list)

    def evaluate(self, text: str) -> CheckResult:
        violations: list[GuardrailViolation] = []
        blocked = False

        for rule in self.rules:
            if rule.matches(text):
                violations.append(
                    GuardrailViolation(
                        rule_id=rule.id,
                        severity=rule.severity,
                        message=rule.description,
                    )
                )
                if rule.action == PolicyAction.BLOCK:
                    blocked = True

        return CheckResult(
            safe=len(violations) == 0,
            violations=violations,
            blocked=blocked,
        )

    def add_rule(self, rule: PolicyRule) -> Policy:
        self.rules.append(rule)
        return self


# ---------------------------------------------------------------------------
# Built-in clinical policies
# ---------------------------------------------------------------------------

def clinical_safety_policy() -> Policy:
    """
    Opinionated default policy for clinical AI applications.

    Blocks responses that attempt to provide specific diagnoses, prescribe
    medication dosages beyond OTC guidance, or encourage patients to ignore
    their healthcare provider.
    """
    return Policy(
        name="clinical-safety",
        description="Baseline safety policy for clinical AI assistants",
        rules=[
            PolicyRule(
                id="CS-001",
                description="Do not provide specific diagnoses — direct user to a clinician",
                action=PolicyAction.BLOCK,
                severity=ViolationSeverity.CRITICAL,
                pattern=(
                    r"\b(you have|you are diagnosed with|diagnosis is|"
                    r"you suffer from|you're suffering from)\b"
                ),
            ),
            PolicyRule(
                id="CS-002",
                description=(
                    "Do not prescribe or recommend specific prescription medications by name"
                ),
                action=PolicyAction.FLAG,
                severity=ViolationSeverity.HIGH,
                pattern=(
                    r"\b(take|prescribe|recommend|use)\s+"
                    r"(amoxicillin|metformin|lisinopril|atorvastatin|"
                    r"sertraline|omeprazole|levothyroxine|amlodipine|"
                    r"metoprolol|albuterol)\b"
                ),
            ),
            PolicyRule(
                id="CS-003",
                description="Do not advise patients to ignore or override their doctor",
                action=PolicyAction.BLOCK,
                severity=ViolationSeverity.CRITICAL,
                pattern=(
                    r"\b(ignore your doctor|don'?t listen to your (doctor|physician|"
                    r"clinician|specialist)|stop taking your (medication|medicine|meds)"
                    r"\s+without)\b"
                ),
            ),
            PolicyRule(
                id="CS-004",
                description="Flag responses that assert certainty about prognosis",
                action=PolicyAction.FLAG,
                severity=ViolationSeverity.HIGH,
                pattern=(
                    r"\b(you will (definitely|certainly|absolutely) (recover|die|"
                    r"survive|get worse|improve)|guaranteed to)\b"
                ),
            ),
        ],
    )


def no_phi_in_prompt_policy() -> Policy:
    """Policy that flags prompts containing likely PHI before they reach an LLM."""
    return Policy(
        name="no-phi-in-prompt",
        description="Prevent PHI from being sent to an external LLM",
        rules=[
            PolicyRule(
                id="PHI-001",
                description="Prompt contains what appears to be an SSN",
                action=PolicyAction.BLOCK,
                severity=ViolationSeverity.CRITICAL,
                pattern=r"\b\d{3}-\d{2}-\d{4}\b",
            ),
            PolicyRule(
                id="PHI-002",
                description="Prompt contains what appears to be a US phone number",
                action=PolicyAction.FLAG,
                severity=ViolationSeverity.MEDIUM,
                pattern=r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
            ),
            PolicyRule(
                id="PHI-003",
                description="Prompt contains what appears to be a date of birth pattern",
                action=PolicyAction.FLAG,
                severity=ViolationSeverity.MEDIUM,
                pattern=r"\b(dob|date of birth|born on|born:)\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
            ),
        ],
    )
