from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any


@dataclass(frozen=True, slots=True)
class Entity:
    """A detected PII span using Python's half-open character offsets."""

    entity_type: str
    start: int
    end: int
    score: float
    source: str
    text: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError(f"Invalid entity span: {self.start}:{self.end}")

    @property
    def length(self) -> int:
        return self.end - self.start

    def safe_dict(self) -> dict[str, Any]:
        fingerprint = sha256(self.text.casefold().encode("utf-8")).hexdigest()[:12]
        return {
            "entity_type": self.entity_type,
            "start": self.start,
            "end": self.end,
            "score": round(self.score, 4),
            "source": self.source,
            "fingerprint": fingerprint,
        }


@dataclass(slots=True)
class PipelineReport:
    input_file: str
    output_file: str
    detected_by_type: Counter[str] = field(default_factory=Counter)
    replacements_by_surface: Counter[str] = field(default_factory=Counter)
    processed_story_parts: int = 0
    processed_paragraphs: int = 0
    processed_images: int = 0
    images_with_redactions: int = 0
    original_value_leaks: int = 0
    metadata_scrubbed: bool = False
    comments_removed: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def total_replacements(self) -> int:
        return sum(self.detected_by_type.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_file": self.input_file,
            "output_file": self.output_file,
            "total_replacements": self.total_replacements,
            "detected_by_type": dict(sorted(self.detected_by_type.items())),
            "replacements_by_surface": dict(sorted(self.replacements_by_surface.items())),
            "processed_story_parts": self.processed_story_parts,
            "processed_paragraphs": self.processed_paragraphs,
            "processed_images": self.processed_images,
            "images_with_redactions": self.images_with_redactions,
            "original_value_leaks": self.original_value_leaks,
            "metadata_scrubbed": self.metadata_scrubbed,
            "comments_removed": self.comments_removed,
            "warnings": self.warnings,
        }
