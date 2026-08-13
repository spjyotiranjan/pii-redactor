from __future__ import annotations

import re
from typing import Any, Iterable

from ..core.config import ImageConfig


class ImageClassifier:
    """Classifies whole images before character-level OCR redaction."""

    def __init__(self, config: ImageConfig) -> None:
        self.config = config

    def classify(self, image: Any, lines: Iterable[Any]) -> str | None:
        lines = list(lines)
        if self._is_sensitive_id(lines):
            return "ID_DOCUMENT"
        if self.config.replace_qr_codes and self._is_qr_code(image):
            return "QR_CODE"
        if self.config.replace_company_logos and self._is_company_logo(image, lines):
            return "COMPANY_LOGO"
        return None

    @staticmethod
    def joined_text(lines: Iterable[Any]) -> str:
        return " ".join(line.text for line in lines if line.text.strip()).strip()

    @classmethod
    def _is_sensitive_id(cls, lines: list[Any]) -> bool:
        text = cls.joined_text(lines).casefold()
        strong_markers = (
            "permanent account number",
            "income tax department",
            "unique identification authority",
            "aadhaar",
            "aadhar",
            "government of india",
            "govt. of india",
        )
        if any(marker in text for marker in strong_markers):
            return True
        has_pan = bool(re.search(r"\b[a-z]{5}\s*\d{4}\s*[a-z]\b", text))
        has_aadhaar = bool(re.search(r"\b[2-9]\d{3}\s+\d{4}\s+\d{4}\b", text))
        identity_context = any(
            marker in text
            for marker in ("date of birth", "dob", "father", "signature", "male", "female")
        )
        return (has_pan or has_aadhaar) and identity_context

    def _is_company_logo(self, image: Any, lines: list[Any]) -> bool:
        reliable_text = " ".join(
            line.text for line in lines
            if line.score >= self.config.minimum_ocr_score and line.text.strip()
        ).casefold()
        if not reliable_text:
            return False

        normalized = re.sub(r"[^a-z0-9]+", " ", reliable_text).strip()
        keyword_match = any(
            re.search(rf"\b{re.escape(keyword.casefold())}\b", normalized)
            for keyword in self.config.logo_keywords
        )
        if keyword_match:
            return True

        company_words = (
            "bank",
            "corporation",
            "holdings",
            "industries",
            "limited",
            "ltd",
            "securities",
            "technologies",
        )
        compact_image = image.width <= 800 and image.height <= 250
        return compact_image and any(re.search(rf"\b{word}\b", normalized) for word in company_words)

    @staticmethod
    def _is_qr_code(image: Any) -> bool:
        try:
            import cv2
            import numpy as np

            pixels = np.asarray(image.convert("RGB"))
            detector = cv2.QRCodeDetector()
            _value, points, _straight = detector.detectAndDecode(pixels)
            if points is not None:
                return True
            detected, _points = detector.detect(pixels)
            return bool(detected)
        except Exception:
            return False
