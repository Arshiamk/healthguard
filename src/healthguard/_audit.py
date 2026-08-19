"""Audit trail: structured, append-only log of every guardrail evaluation."""

from __future__ import annotations

import hashlib
from typing import IO, Any

from healthguard._models import AuditEntry, CheckResult, RedactionResult


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class AuditLog:
    """In-process audit log that writes newline-delimited JSON.

    Suitable for local development and testing.  In production, replace the
    sink with a call to a SIEM, a structured logging library (structlog), or
    an append-only datastore.

    Args:
        sink: A writable file-like object.  Defaults to an in-memory list
            that you can read via :attr:`entries`.
    """

    def __init__(self, sink: IO[str] | None = None) -> None:
        self._sink = sink
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def record_check(
        self,
        *,
        event: str,
        text: str,
        result: CheckResult,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            event=event,
            prompt_hash=_sha256(text),
            check_result=result,
            metadata=metadata or {},
        )
        self._append(entry)
        return entry

    def record_redaction(
        self,
        *,
        text: str,
        result: RedactionResult,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            event="phi_redaction",
            prompt_hash=_sha256(text),
            redaction_result=result,
            metadata=metadata or {},
        )
        self._append(entry)
        return entry

    def _append(self, entry: AuditEntry) -> None:
        self._entries.append(entry)
        if self._sink is not None:
            self._sink.write(entry.model_dump_json() + "\n")
            self._sink.flush()

    def export_jsonl(self) -> str:
        """Return all entries as a JSONL string."""
        return "\n".join(e.model_dump_json() for e in self._entries)

    def clear(self) -> None:
        self._entries.clear()
