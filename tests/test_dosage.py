"""Tests for the dosage safety guardrail."""

import pytest

from healthguard.guardrails._dosage import DosageGuardrail


@pytest.fixture
def guard() -> DosageGuardrail:
    return DosageGuardrail()


def test_safe_otc_ibuprofen(guard: DosageGuardrail) -> None:
    result = guard.check("Take 400mg of ibuprofen every 6–8 hours, up to 1200mg per day.")
    assert result.safe


def test_exceeds_single_dose_ibuprofen(guard: DosageGuardrail) -> None:
    result = guard.check("Take 800mg of ibuprofen every 4 hours.")
    assert not result.safe
    assert any(v.rule_id == "DOSE-001" for v in result.violations)


def test_exceeds_daily_limit_ibuprofen(guard: DosageGuardrail) -> None:
    result = guard.check(
        "Take 400mg of ibuprofen every 4 hours, up to 3000mg per day."
    )
    assert not result.safe
    assert any(v.rule_id == "DOSE-002" for v in result.violations)


def test_safe_acetaminophen(guard: DosageGuardrail) -> None:
    result = guard.check("You can take 500mg of acetaminophen every 6 hours, max 2000mg per day.")
    assert result.safe


def test_exceeds_daily_acetaminophen(guard: DosageGuardrail) -> None:
    result = guard.check(
        "Take 1000mg of acetaminophen every 4 hours, up to 6000mg per day."
    )
    assert not result.safe


def test_no_dosage_mention(guard: DosageGuardrail) -> None:
    result = guard.check("Rest and drink plenty of fluids.")
    assert result.safe
    assert len(result.violations) == 0


def test_violation_has_remediation(guard: DosageGuardrail) -> None:
    result = guard.check("Take 600mg of ibuprofen every 4 hours.")
    assert any(v.remediation for v in result.violations)
