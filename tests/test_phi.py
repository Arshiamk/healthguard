"""Tests for the PHI redactor."""

import pytest

from healthguard.guardrails._phi import PHIRedactor


@pytest.fixture
def redactor() -> PHIRedactor:
    return PHIRedactor()


def test_redacts_ssn(redactor: PHIRedactor) -> None:
    result = redactor.redact("Patient SSN: 123-45-6789")
    assert "123-45-6789" not in result.redacted
    assert "[SSN]" in result.redacted
    assert result.was_modified


def test_redacts_email(redactor: PHIRedactor) -> None:
    result = redactor.redact("Contact: john.smith@hospital.org for details")
    assert "john.smith@hospital.org" not in result.redacted
    assert "[EMAIL]" in result.redacted


def test_redacts_phone(redactor: PHIRedactor) -> None:
    result = redactor.redact("Call the patient at 555-867-5309")
    assert "555-867-5309" not in result.redacted
    assert "[PHONE]" in result.redacted


def test_redacts_date(redactor: PHIRedactor) -> None:
    result = redactor.redact("DOB: 1990-06-15")
    assert "1990-06-15" not in result.redacted


def test_clean_text_unchanged(redactor: PHIRedactor) -> None:
    text = "The patient reported moderate headache and fatigue."
    result = redactor.redact(text)
    assert not result.was_modified
    assert result.redacted == text


def test_is_clean_returns_false_for_phi(redactor: PHIRedactor) -> None:
    assert not redactor.is_clean("SSN 000-12-3456")


def test_is_clean_returns_true_for_safe_text(redactor: PHIRedactor) -> None:
    assert redactor.is_clean("Blood pressure was 120/80 mmHg.")


def test_multiple_entities_in_one_text(redactor: PHIRedactor) -> None:
    text = "Patient John Smith, DOB 1980-03-15, phone 555-123-4567, SSN 987-65-4321"
    result = redactor.redact(text)
    assert "John Smith" not in result.redacted
    assert "1980-03-15" not in result.redacted
    assert "555-123-4567" not in result.redacted
    assert "987-65-4321" not in result.redacted
    assert result.redaction_count >= 3
