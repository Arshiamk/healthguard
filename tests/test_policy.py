"""Tests for the policy engine."""

from healthguard._policy import (
    Policy,
    PolicyAction,
    PolicyRule,
    ViolationSeverity,
    clinical_safety_policy,
    no_phi_in_prompt_policy,
)


def test_custom_policy_flag() -> None:
    policy = Policy(name="test")
    policy.add_rule(PolicyRule(
        id="T-001",
        description="No mentions of competitors",
        action=PolicyAction.FLAG,
        severity=ViolationSeverity.LOW,
        pattern=r"\bcompetitor\b",
    ))
    result = policy.evaluate("Our competitor does this differently.")
    assert not result.safe
    assert not result.blocked  # FLAG, not BLOCK


def test_custom_policy_block() -> None:
    policy = Policy(name="test")
    policy.add_rule(PolicyRule(
        id="T-002",
        description="No explicit self-harm content",
        action=PolicyAction.BLOCK,
        severity=ViolationSeverity.CRITICAL,
        pattern=r"\bhow to harm\b",
    ))
    result = policy.evaluate("Here is how to harm yourself.")
    assert result.blocked


def test_clinical_safety_blocks_diagnosis() -> None:
    policy = clinical_safety_policy()
    result = policy.evaluate("Based on your symptoms, you have type 2 diabetes.")
    assert not result.safe
    assert result.blocked
    assert any(v.rule_id == "CS-001" for v in result.violations)


def test_clinical_safety_flags_prescription_drug() -> None:
    policy = clinical_safety_policy()
    result = policy.evaluate("I recommend you take metformin for your blood sugar.")
    assert not result.safe
    assert any(v.rule_id == "CS-002" for v in result.violations)


def test_clinical_safety_passes_general_advice() -> None:
    policy = clinical_safety_policy()
    result = policy.evaluate(
        "A balanced diet, regular exercise, and stress management are important for overall health."
    )
    assert result.safe


def test_no_phi_blocks_ssn_in_prompt() -> None:
    policy = no_phi_in_prompt_policy()
    result = policy.evaluate("Patient SSN is 123-45-6789, please summarise their record.")
    assert result.blocked
    assert any(v.rule_id == "PHI-001" for v in result.violations)


def test_policy_callable_matcher() -> None:
    def long_text(text: str) -> bool:
        return len(text) > 500

    policy = Policy(name="test")
    policy.add_rule(PolicyRule(
        id="T-003",
        description="Input too long",
        action=PolicyAction.FLAG,
        severity=ViolationSeverity.LOW,
        matcher=long_text,
    ))
    short_result = policy.evaluate("Short text.")
    long_result = policy.evaluate("x" * 501)
    assert short_result.safe
    assert not long_result.safe
