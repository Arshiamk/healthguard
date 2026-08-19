"""HealthGuard core orchestrator.

This is the single entry point for most users.  It wires together all
guardrails and policies into a simple, composable API.
"""

from __future__ import annotations

from typing import Any

from healthguard._audit import AuditLog
from healthguard._models import CheckResult, GuardrailViolation, RedactionResult
from healthguard._policy import Policy, clinical_safety_policy, no_phi_in_prompt_policy
from healthguard.guardrails._dosage import DosageGuardrail
from healthguard.guardrails._phi import PHIRedactor
from healthguard.guardrails._prompt_injection import PromptInjectionGuardrail


class HealthGuard:
    """Composable clinical AI guardrails.

    Args:
        policies: Additional :class:`~healthguard.Policy` objects to evaluate.
            The built-in clinical safety policy is always included unless
            ``use_defaults=False``.
        use_defaults: Include the built-in clinical safety and no-PHI policies.
            Defaults to ``True``.
        audit: An :class:`~healthguard._audit.AuditLog` instance.  If
            ``None``, a new in-memory log is created automatically.
        redact_icd: Pass-through to :class:`~healthguard.guardrails.PHIRedactor`.
    """

    def __init__(
        self,
        policies: list[Policy] | None = None,
        use_defaults: bool = True,
        audit: AuditLog | None = None,
        redact_icd: bool = False,
    ) -> None:
        self._phi = PHIRedactor(redact_icd=redact_icd)
        self._dosage = DosageGuardrail()
        self._injection = PromptInjectionGuardrail()
        self._audit = audit or AuditLog()

        self._policies: list[Policy] = []
        if use_defaults:
            self._policies.append(clinical_safety_policy())
            self._policies.append(no_phi_in_prompt_policy())
        if policies:
            self._policies.extend(policies)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def audit(self) -> AuditLog:
        return self._audit

    def redact(self, text: str, *, metadata: dict[str, Any] | None = None) -> str:
        """Redact PHI from *text* and return the safe string.

        The original and redacted texts are recorded in the audit log.
        Use :meth:`redact_full` if you need the full :class:`RedactionResult`.
        """
        return self.redact_full(text, metadata=metadata).redacted

    def redact_full(
        self, text: str, *, metadata: dict[str, Any] | None = None
    ) -> RedactionResult:
        """Redact PHI and return the full :class:`RedactionResult`."""
        result = self._phi.redact(text)
        self._audit.record_redaction(text=text, result=result, metadata=metadata)
        return result

    def check_prompt(
        self,
        prompt: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Run all guardrails against a user *prompt* before sending to the LLM.

        Checks for:
        - Prompt injection attempts
        - PHI present in the prompt (flags; use :meth:`redact` to clean first)
        - Policy rule violations
        """
        violations: list[GuardrailViolation] = []
        blocked = False

        injection_result = self._injection.check(prompt)
        violations.extend(injection_result.violations)
        blocked = blocked or injection_result.blocked

        for policy in self._policies:
            if policy.name == "no-phi-in-prompt":
                pol_result = policy.evaluate(prompt)
                violations.extend(pol_result.violations)
                blocked = blocked or pol_result.blocked

        result = CheckResult(safe=len(violations) == 0, violations=violations, blocked=blocked)
        self._audit.record_check(
            event="prompt_check", text=prompt, result=result, metadata=metadata
        )
        return result

    def check_response(
        self,
        response: str,
        *,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Run all guardrails against an LLM *response* before surfacing to the user.

        Checks for:
        - Dosage safety violations
        - Clinical safety policy violations
        """
        violations: list[GuardrailViolation] = []
        blocked = False

        dosage_result = self._dosage.check(response)
        violations.extend(dosage_result.violations)
        blocked = blocked or dosage_result.blocked

        for policy in self._policies:
            if policy.name == "clinical-safety":
                pol_result = policy.evaluate(response)
                violations.extend(pol_result.violations)
                blocked = blocked or pol_result.blocked

        result = CheckResult(
            safe=len(violations) == 0,
            violations=violations,
            blocked=blocked,
            metadata=context or {},
        )
        self._audit.record_check(
            event="response_check", text=response, result=result, metadata=metadata
        )
        return result

    def add_policy(self, policy: Policy) -> HealthGuard:
        """Attach an additional :class:`Policy`.  Returns ``self`` for chaining."""
        self._policies.append(policy)
        return self
