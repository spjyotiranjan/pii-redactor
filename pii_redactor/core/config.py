from __future__ import annotations

from dataclasses import dataclass, field


DEFAULT_ENTITY_TYPES = (
    "PERSON",
    "EMAIL_ADDRESS",
    "WEBSITE",
    "PHONE_NUMBER",
    "COMPANY",
    "ADDRESS",
    "US_SSN",
    "CREDIT_CARD",
    "DATE_OF_BIRTH",
    "IP_ADDRESS",
    "IN_PAN",
    "IN_AADHAAR",
    "IN_GSTIN",
    "IN_CIN",
    "IN_DIN",
)


@dataclass(slots=True)
class DetectorConfig:
    """Text detection policy."""

    enabled_entities: tuple[str, ...] = DEFAULT_ENTITY_TYPES
    presidio_score_threshold: float = 0.55
    enable_presidio: bool = True
    enable_heuristic_ner: bool = True
    redact_single_token_person_names: bool = False
    allow_list: set[str] = field(
        default_factory=lambda: {
            "red herring prospectus",
            "the company",
            "our company",
            "company",
            "issuer",
            "order",
            "ticket",
            "india",
            "equity shares",
            "book running lead manager",
        }
    )


@dataclass(slots=True)
class ImageConfig:
    """Controls OCR and replacement of sensitive embedded images."""

    minimum_ocr_score: float = 0.50
    replace_company_logos: bool = True
    replace_qr_codes: bool = True
    logo_keywords: tuple[str, ...] = (
        "icici",
        "ksh",
        "mufg",
        "nuvama",
        "securities",
    )


@dataclass(slots=True)
class PipelineConfig:
    redact_images: bool = True
    remove_comments: bool = True
    remove_tracked_deletions: bool = True
    scrub_metadata: bool = True
    preserve_original_file: bool = True
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    images: ImageConfig = field(default_factory=ImageConfig)
