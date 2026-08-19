"""PHI (Protected Health Information) redactor.

Detects and replaces common PHI patterns with labelled placeholders so that
text can be safely passed to an external LLM without leaking patient data.

This is a regex-based heuristic layer — not a substitute for a full NLP NER
pipeline in production.  Pair with a proper NER model (e.g. spaCy with the
en_core_sci_lg model) for higher recall on free-text clinical notes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from healthguard._models import RedactionResult


@dataclass
class _Pattern:
    label: str
    regex: str
    flags: int = re.IGNORECASE


# Ordered from most-specific to least-specific to avoid partial overwrites.
_PHI_PATTERNS: list[_Pattern] = [
    # Social Security Number
    _Pattern("SSN", r"\b\d{3}-\d{2}-\d{4}\b", 0),
    # US phone numbers in multiple formats
    _Pattern(
        "PHONE",
        r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
        0,
    ),
    # Email addresses
    _Pattern("EMAIL", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0),
    # ISO dates and common date formats
    _Pattern(
        "DATE",
        r"\b(\d{4}-\d{2}-\d{2}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b",
        0,
    ),
    # US ZIP codes (5-digit and ZIP+4)
    _Pattern("ZIP", r"\b\d{5}(-\d{4})?\b", 0),
    # Medical Record Number patterns (MRN: followed by digits)
    _Pattern("MRN", r"\bMRN\s*:?\s*\d+\b", re.IGNORECASE),
    # Names preceded by Title Case clinical labels followed by a Title Case name.
    # Requires "Patient", "Pt", or "Name" (capitalised) to avoid matching free-text
    # sentences like "the patient reported...".
    _Pattern(
        "NAME",
        r"\b(?:Patient|Pt\.?|Name)\s*:?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})"
        r"(?=\s*[,.\n]|\s+[a-z]|\s*\Z)",
        0,
    ),
    # Date of birth with label
    _Pattern(
        "DATE",
        r"\b(dob|date of birth|born:?)\s*:?\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
        re.IGNORECASE,
    ),
    # NPI numbers (10-digit identifiers)
    _Pattern("NPI", r"\bNPI\s*:?\s*\d{10}\b", re.IGNORECASE),
    # ICD codes when paired with a patient reference (flag, not always PHI)
    _Pattern(
        "ICD",
        r"\b[A-TV-Z][0-9][0-9AB]\.?[0-9A-TV-Z]{0,4}\b",
        0,
    ),
]


class PHIRedactor:
    """Regex-based PHI redactor for clinical text.

    Args:
        extra_patterns: Additional ``_Pattern``-compatible dicts or ``_Pattern``
            instances to include on top of the built-in set.
        redact_icd: Whether to redact ICD-10 codes. Defaults to ``False``
            because ICD codes are not inherently PHI — they become PHI only
            when combined with identifiable information.
    """

    def __init__(
        self,
        extra_patterns: list[_Pattern] | None = None,
        redact_icd: bool = False,
    ) -> None:
        self._patterns = [
            p for p in _PHI_PATTERNS if p.label != "ICD" or redact_icd
        ]
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def redact(self, text: str) -> RedactionResult:
        """Redact PHI from *text*, returning both the redacted string and metadata."""
        result = text
        entities_found: list[str] = []
        count = 0

        for pattern in self._patterns:
            compiled = re.compile(pattern.regex, pattern.flags)
            matches = compiled.findall(result)
            if matches:
                entities_found.append(pattern.label)
                count += len(matches)
                result = compiled.sub(f"[{pattern.label}]", result)

        return RedactionResult(
            original=text,
            redacted=result,
            entities_found=list(dict.fromkeys(entities_found)),  # deduplicate, keep order
            redaction_count=count,
        )

    def is_clean(self, text: str) -> bool:
        """Return ``True`` if no PHI patterns are detected in *text*."""
        return not self.redact(text).was_modified
