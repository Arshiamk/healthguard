"""Shared data models for HealthGuard."""

from __future__ import annotations

import datetime
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ViolationSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GuardrailViolation(BaseModel):
    """A single rule violation detected in a prompt or response."""

    rule_id: str
    severity: ViolationSeverity
    message: str
    evidence: str | None = None
    remediation: str | None = None


class CheckResult(BaseModel):
    """Result of running guardrails against a model prompt or response."""

    safe: bool
    violations: list[GuardrailViolation] = Field(default_factory=list)
    blocked: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def has_critical(self) -> bool:
        return any(v.severity == ViolationSeverity.CRITICAL for v in self.violations)


class RedactionResult(BaseModel):
    """Result of PHI/PII redaction."""

    original: str
    redacted: str
    entities_found: list[str] = Field(default_factory=list)
    redaction_count: int = 0

    @property
    def was_modified(self) -> bool:
        return self.original != self.redacted


class AuditEntry(BaseModel):
    """Immutable audit log entry for a guardrail evaluation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )
    event: str
    prompt_hash: str | None = None
    response_hash: str | None = None
    check_result: CheckResult | None = None
    redaction_result: RedactionResult | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
