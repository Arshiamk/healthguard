"""Prompt injection guardrail for clinical AI systems.

Detects attempts to override system instructions, extract system prompts,
or jailbreak a clinical assistant into unsafe behaviour.

Clinical systems are high-value targets because an attacker who bypasses
guardrails could receive content that a patient acts on medically.
"""

from __future__ import annotations

import re

from healthguard._models import CheckResult, GuardrailViolation, ViolationSeverity

_INJECTION_PATTERNS: list[tuple[str, str, ViolationSeverity]] = [
    # Direct instruction override attempts
    (
        "INJECT-001",
        r"\b(ignore (previous|all|prior|above) instructions?|"
        r"disregard (your|the) (system|safety|clinical) (prompt|instructions?)|"
        r"forget (everything|all) (you('ve| have) been told|above))\b",
        ViolationSeverity.CRITICAL,
    ),
    # System prompt extraction
    (
        "INJECT-002",
        r"\b(reveal|show|print|output|repeat|tell me) (your|the) "
        r"(system (prompt|message|instructions?)|initial (prompt|instructions?))\b",
        ViolationSeverity.HIGH,
    ),
    # Role-play / persona switching
    (
        "INJECT-003",
        r"\b(pretend (you are|to be)|act as|roleplay as|you are now|"
        r"from now on (you are|act as)|imagine you('re| are))\b",
        ViolationSeverity.HIGH,
    ),
    # Jailbreak keywords specific to medical context
    (
        "INJECT-004",
        r"\b(DAN|do anything now|jailbreak|uncensored (doctor|physician|AI)|"
        r"unrestricted medical|bypass (safety|guardrails?|restrictions?))\b",
        ViolationSeverity.CRITICAL,
    ),
    # Encoding / obfuscation attempts
    (
        "INJECT-005",
        r"(base64|rot13|hex decode|\\u00|%[0-9a-fA-F]{2}.*ignore)",
        ViolationSeverity.MEDIUM,
    ),
]

_COMPILED = [
    (rule_id, re.compile(pattern, re.IGNORECASE), severity)
    for rule_id, pattern, severity in _INJECTION_PATTERNS
]


class PromptInjectionGuardrail:
    """Detect prompt injection attempts before they reach an LLM."""

    def check(self, prompt: str) -> CheckResult:
        violations: list[GuardrailViolation] = []

        for rule_id, regex, severity in _COMPILED:
            match = regex.search(prompt)
            if match:
                violations.append(
                    GuardrailViolation(
                        rule_id=rule_id,
                        severity=severity,
                        message=f"Possible prompt injection detected ({rule_id}).",
                        evidence=match.group(0),
                        remediation="Reject this input and do not forward it to the model.",
                    )
                )

        blocked = any(v.severity == ViolationSeverity.CRITICAL for v in violations)

        return CheckResult(
            safe=len(violations) == 0,
            violations=violations,
            blocked=blocked,
        )
