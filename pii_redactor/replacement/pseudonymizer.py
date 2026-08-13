from __future__ import annotations

import re
from datetime import date


class DeterministicPseudonymizer:
    """Maps every PII type to a stable, unmistakably generic template value."""

    def __init__(self, seed: str) -> None:
        self.seed = seed
        self._mapping: dict[tuple[str, str], str] = {}
        self._originals: dict[tuple[str, str], str] = {}

    @property
    def originals(self) -> list[str]:
        return list(self._originals.values())

    @property
    def original_items(self) -> list[tuple[str, str]]:
        return [(entity_type, original) for (entity_type, _), original in self._originals.items()]

    def replace(self, entity_type: str, original: str) -> str:
        normalized = self._normalize(entity_type, original)
        key = (entity_type, normalized)
        if key not in self._mapping:
            fake = self._generate(entity_type, original, normalized)
            self._mapping[key] = fake
            self._originals[key] = original
        return self._mapping[key]

    @staticmethod
    def _normalize(entity_type: str, value: str) -> str:
        if entity_type in {"PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IN_AADHAAR", "IN_DIN"}:
            return re.sub(r"\D", "", value)
        return re.sub(r"\s+", " ", value).strip().casefold()

    def _generate(self, entity_type: str, original: str, normalized: str) -> str:
        if entity_type == "PERSON":
            return self._copy_case(original, "John Doe")
        if entity_type == "EMAIL_ADDRESS":
            return "john.doe@example.com"
        if entity_type == "WEBSITE":
            return "www.example.com"
        if entity_type == "PHONE_NUMBER":
            digits = re.sub(r"\D", "", original)
            replacement_digits = self._phone_digits(digits, original)
            return self._apply_digit_format(original, replacement_digits)
        if entity_type == "COMPANY":
            return self._copy_case(original, self._generic_company(original))
        if entity_type == "ADDRESS":
            return self._copy_case(original, "123 Example Street, Sample City 100001, India")
        if entity_type == "US_SSN":
            return self._apply_digit_format(original, "000123456")
        if entity_type == "CREDIT_CARD":
            length = len(re.sub(r"\D", "", original))
            return self._apply_digit_format(original, self._test_card_digits(length))
        if entity_type == "DATE_OF_BIRTH":
            return self._generic_date(original)
        if entity_type == "IP_ADDRESS":
            if ":" in original:
                return "2001:db8::1"
            return "192.0.2.1"
        if entity_type == "IN_PAN":
            return "ABCDE0000A"
        if entity_type == "IN_AADHAAR":
            return self._apply_digit_format(original, "200000000000")
        if entity_type == "IN_GSTIN":
            return "27ABCDE0000A1Z0"
        if entity_type == "IN_CIN":
            return "U00000MH2020PTC000000"
        if entity_type == "IN_DIN":
            return "00000000"
        return f"[{entity_type}]"

    @staticmethod
    def _copy_case(original: str, replacement: str) -> str:
        letters = [c for c in original if c.isalpha()]
        if letters and all(c.isupper() for c in letters):
            return replacement.upper()
        if letters and all(c.islower() for c in letters):
            return replacement.lower()
        return replacement

    @staticmethod
    def _generic_company(original: str) -> str:
        lowered = original.casefold()
        if "bank" in lowered:
            return "Example Bank Limited"
        if "trust" in lowered:
            return "Example Trust"
        if re.search(r"\bllp\b", lowered):
            return "Example Advisory LLP"
        if re.search(r"\b(private|pvt)\b", lowered):
            return "Example Company Private Limited"
        return "Example Company Limited"

    @staticmethod
    def _phone_digits(original_digits: str, original: str) -> str:
        length = len(original_digits)
        if original.lstrip().startswith("+") and original_digits.startswith("91") and length >= 12:
            return ("917" + "0" * length)[:length]
        if length == 10:
            return "7000000000"
        return ("5" + "0" * length)[:length]

    @staticmethod
    def _apply_digit_format(template: str, digits: str) -> str:
        iterator = iter(digits)
        result: list[str] = []
        for char in template:
            result.append(next(iterator, "0") if char.isdigit() else char)
        result.extend(iterator)
        return "".join(result)

    @staticmethod
    def _test_card_digits(length: int) -> str:
        length = min(19, max(13, length))
        body = "4" + "1" * (length - 2)
        for check in range(10):
            candidate = body + str(check)
            total = 0
            parity = len(candidate) % 2
            for index, char in enumerate(candidate):
                value = int(char)
                if index % 2 == parity:
                    value = value * 2 - 9 if value >= 5 else value * 2
                total += value
            if total % 10 == 0:
                return candidate
        raise AssertionError("Could not generate a Luhn-valid test number")

    @staticmethod
    def _generic_date(original: str) -> str:
        formats = (
            "%d-%m-%Y",
            "%d/%m/%Y",
            "%d.%m.%Y",
            "%d %B %Y",
            "%d %b %Y",
            "%B %d, %Y",
            "%B %d %Y",
            "%b %d, %Y",
            "%b %d %Y",
        )
        from datetime import datetime

        used_format = ""
        for fmt in formats:
            try:
                datetime.strptime(original.strip(), fmt)
                used_format = fmt
                break
            except ValueError:
                continue
        if not used_format:
            return "01 January 1990"
        return date(1990, 1, 1).strftime(used_format)
