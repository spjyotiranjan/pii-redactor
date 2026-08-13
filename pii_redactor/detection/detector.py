from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable

from ..core.config import DetectorConfig
from ..core.models import Entity


Recognizer = Callable[[str], Iterable[Entity]]


class PiiDetector:
    """Hybrid recognizer: validated rules first, Presidio NER second, heuristics last."""

    EMAIL_RE = re.compile(
        r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![\w-])",
        re.IGNORECASE,
    )
    WEBSITE_RE = re.compile(
        r"(?ix)(?<![@\w])"
        r"(?:https?\s*:\s*/\s*/\s*|www\s*\.)"
        r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?"
        r"(?:\s*\.\s*[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+"
        r"(?:\s*/\s*[^\s<>()\[\]{}]*)?"
    )
    PHONE_RE = re.compile(
        r"(?<![\w\d])(?:\+\s?\d{1,3}[\s().-]*)?"
        r"(?:\(?\d{2,5}\)?[\s.-]*)?(?:\d[\s.-]*){7,12}\d(?!\d)"
    )
    SSN_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}(?!\d)")
    CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
    IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
    IPV6_RE = re.compile(r"(?<![\w:])(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{0,4}(?![\w:])", re.IGNORECASE)
    PAN_RE = re.compile(r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])")
    AADHAAR_RE = re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)")
    GSTIN_RE = re.compile(r"(?<![A-Z0-9])\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z](?![A-Z0-9])")
    CIN_RE = re.compile(r"(?<![A-Z0-9])[UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}(?![A-Z0-9])")
    DIN_RE = re.compile(r"(?<!\d)\d{8}(?!\d)")
    DOB_RE = re.compile(
        r"(?ix)\b(?:date\s+of\s+birth|d\.?\s*o\.?\s*b\.?|born\s+on|birth\s+date)\b"
        r"\s*(?:is|:|-)?\s*"
        r"(?P<date>"
        r"(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}"
        r"|(?:0?[1-9]|[12]\d|3[01])\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:19|20)\d{2}"
        r"|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:0?[1-9]|[12]\d|3[01]),?\s+(?:19|20)\d{2}"
        r")"
    )

    COMPANY_RE = re.compile(
        r"(?x)(?<![\w])"
        r"(?!OF\b)"
        r"(?:[A-Z][A-Za-z0-9&.'’-]*)"
        r"(?:\s+(?:[A-Z][A-Za-z0-9&.'’()/-]*|and|of|the|&)){0,10}\s+"
        r"(?i:PRIVATE\s+LIMITED|PVT\.?\s+LTD\.?|LIMITED|LTD\.?|LLP|INC\.?|INCORPORATED|"
        r"CORPORATION|CORP\.?|PLC|BANK|TRUST|FOUNDATION|ASSOCIATION|UNIVERSITY|HOSPITAL)"
        r"(?![\w])"
    )
    HONORIFIC_PERSON_RE = re.compile(
        r"(?<!\w)(?i:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+"
        r"(?P<name>[A-Z][A-Za-z'’-]+(?:\s+[A-Z][A-Za-z'’-]+){1,3})"
    )
    ROLE_PERSON_RE = re.compile(
        r"(?<!\w)(?P<name>[A-Z][A-Za-z'’-]+(?:\s+[A-Z][A-Za-z'’-]+){1,3})"
        r"(?=\s*[,;:-]?\s*(?:Company\s+Secretary|Director|Promoter|Compliance\s+Officer|"
        r"Chief\s+Executive|Chief\s+Financial|Managing\s+Director|Whole[- ]time\s+Director)\b)"
    )
    LABELED_PERSON_RE = re.compile(
        r"(?i:\b(?:contact\s+person|customer|employee|director|promoter|name)\b\s*(?:is|:|-)?\s*)"
        r"(?P<name>[A-Z][A-Za-z'’-]+(?:\s+[A-Z][A-Za-z'’-]+){1,3})"
    )
    ALL_CAPS_NAME_RE = re.compile(r"(?<![A-Z])([A-Z][A-Z'’-]{1,}(?:\s+[A-Z][A-Z'’-]{1,}){1,3})(?![A-Z])")
    FAMILY_BRANCH_RE = re.compile(
        r"(?ix)\b(?:family\s+branch\(es\)|parents\s+branch|branch\s*\(es\)|family\s+branch)\b"
        r"\s*(?:[:;-]|,)?\s*(?P<names>(?:[A-Z][A-Za-z'’-]+\s+branch(?:\s*,\s*|\s+and\s+|\s*\b))+[A-Z][A-Za-z'’-]+\s+branch)"
    )
    CONTEXTUAL_SENSITIVE_RE = re.compile(
        r"(?ix)\b(?:family\s+branch\(es\)|parents\s+branch|our\s+promoters|group\s+companies|"
        r"(?:[A-Z]{1,8}\s+)?employee\s+stock\s+option\s+(?:scheme|plan)|"
        r"(?:[A-Z]{1,8}\s+)?stock\s+option\s+(?:scheme|plan)|esop)\b"
        r"(?:\s+[0-9]{4})?"
    )
    SENSITIVE_HEADINGS_RE = re.compile(
        r"(?ix)\b(?:our\s+promoters|family\s+branch\(es\)|family\s+branch|group\s+companies)\b"
    )
    ESOP_SCHEME_RE = re.compile(
        r"(?ix)\b(?:[A-Z]{1,8}\s+)?(?:employee\s+stock\s+option\s+(?:scheme|plan)|stock\s+option\s+(?:scheme|plan)|esop)\b"
        r"(?:\s+[0-9]{4})?"
    )
    ADDRESS_LABEL_RE = re.compile(
        r"(?is)\b(?:registered|corporate|mailing|postal|residential|business|office)\s+address\b"
        r"\s*(?:is|:|-)?\s*(?P<address>[^\n;]{8,220})"
    )
    ADDRESSISH_RE = re.compile(
        r"(?ix)(?=.*\d)(?=.*\b(?:road|rd|street|st|avenue|ave|lane|ln|sector|plot|floor|"
        r"building|tower|village|taluka|district|nagar|colony|office|pune|mumbai|delhi|"
        r"maharashtra|india|pin|pincode)\b).{12,240}"
    )

    PRECEDENCE = {
        "CREDIT_CARD": 100,
        "US_SSN": 98,
        "IN_AADHAAR": 98,
        "IN_GSTIN": 97,
        "IN_CIN": 97,
        "IN_PAN": 97,
        "IN_DIN": 96,
        "EMAIL_ADDRESS": 95,
        "WEBSITE": 95,
        "IP_ADDRESS": 94,
        "PHONE_NUMBER": 90,
        "DATE_OF_BIRTH": 88,
        "ADDRESS": 75,
        "COMPANY": 70,
        "PERSON": 65,
    }
    NON_PERSON_WORDS = frozenset(
        {
            "act",
            "acknowledgement",
            "acquisition",
            "agents",
            "air",
            "anchor",
            "articles",
            "association",
            "average",
            "bid",
            "bidders",
            "board",
            "book",
            "branch",
            "broker",
            "buyers",
            "company",
            "conditioning",
            "contact",
            "corporate",
            "corrigenda",
            "cost",
            "director",
            "directors",
            "details",
            "depository",
            "defaulter",
            "equity",
            "exchange",
            "face",
            "facility",
            "floor",
            "fresh",
            "funds",
            "general",
            "guidelines",
            "icdr",
            "india",
            "institutional",
            "industrial",
            "issue",
            "issuer",
            "lead",
            "limited",
            "manager",
            "managing",
            "margin",
            "marg",
            "maharashtra",
            "mutual",
            "name",
            "nse",
            "offer",
            "officer",
            "operational",
            "park",
            "parents",
            "participant",
            "person",
            "personnel",
            "photo",
            "price",
            "promoter",
            "promoters",
            "prospectus",
            "public",
            "qualified",
            "red",
            "reference",
            "registered",
            "registrar",
            "regulations",
            "risk",
            "running",
            "sale",
            "sebi",
            "secretary",
            "schedule",
            "secondary",
            "share",
            "shareholder",
            "shareholders",
            "shares",
            "stock",
            "taluka",
            "thereto",
            "transfer",
            "urja",
            "value",
            "voltaic",
            "website",
            "weighted",
            "wilful",
            "the",
            "for",
        }
    )

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()
        self._presidio = None
        self._presidio_attempted = False
        self.presidio_status = "not initialized"

    def analyze(self, text: str) -> list[Entity]:
        if not text or not text.strip():
            return []

        candidates: list[Entity] = []
        candidates.extend(self._structured_entities(text))
        if self.config.enable_presidio:
            candidates.extend(self._presidio_entities(text))
        if self.config.enable_heuristic_ner:
            candidates.extend(self._heuristic_entities(text))

        enabled = set(self.config.enabled_entities)
        candidates = [
            entity
            for entity in candidates
            if entity.entity_type in enabled
            and not self._allowlisted(entity.text)
            and (
                entity.entity_type != "PERSON"
                or self._valid_person_candidate(entity.text)
                or entity.source in {"family-branch-context", "sensitive-heading", "sensitive-context"}
            )
        ]
        return self.resolve_overlaps(candidates)

    def _entity(self, entity_type: str, match: re.Match[str], score: float, source: str, group: str | int = 0) -> Entity:
        start, end = match.span(group)
        return Entity(entity_type, start, end, score, source, match.group(group))

    def _structured_entities(self, text: str) -> list[Entity]:
        found: list[Entity] = []
        found.extend(self._entity("EMAIL_ADDRESS", m, 0.99, "regex") for m in self.EMAIL_RE.finditer(text))
        found.extend(self._entity("WEBSITE", m, 0.99, "regex") for m in self.WEBSITE_RE.finditer(text))
        found.extend(self._entity("US_SSN", m, 0.99, "regex+range") for m in self.SSN_RE.finditer(text))
        found.extend(self._entity("IN_PAN", m, 0.98, "regex") for m in self.PAN_RE.finditer(text))
        found.extend(self._entity("IN_GSTIN", m, 0.99, "regex") for m in self.GSTIN_RE.finditer(text))
        found.extend(self._entity("IN_CIN", m, 0.99, "regex") for m in self.CIN_RE.finditer(text))

        for m in self.CREDIT_CARD_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if 13 <= len(digits) <= 19 and self._luhn_valid(digits):
                found.append(self._entity("CREDIT_CARD", m, 0.995, "regex+luhn"))

        for regex in (self.IPV4_RE, self.IPV6_RE):
            for m in regex.finditer(text):
                try:
                    ipaddress.ip_address(m.group())
                except ValueError:
                    continue
                found.append(self._entity("IP_ADDRESS", m, 0.995, "regex+parser"))

        for m in self.PHONE_RE.finditer(text):
            value = m.group()
            digits = re.sub(r"\D", "", value)
            nearby = text[max(0, m.start() - 24) : min(len(text), m.end() + 8)].casefold()
            has_context = bool(re.search(r"phone|telephone|mobile|contact|call|fax|tel\.?", nearby))
            plausible_indian_mobile = len(digits) == 10 and digits[0] in "6789"
            has_country_prefix = value.lstrip().startswith("+")
            if 7 <= len(digits) <= 15 and (has_context or plausible_indian_mobile or has_country_prefix):
                found.append(self._entity("PHONE_NUMBER", m, 0.9 if has_context else 0.78, "regex+context"))

        for m in self.AADHAAR_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if len(set(digits)) > 2:
                found.append(self._entity("IN_AADHAAR", m, 0.94, "regex"))

        for m in self.DIN_RE.finditer(text):
            nearby = text[max(0, m.start() - 20) : m.start()].casefold()
            if re.search(r"\b(?:din|director identification number)\b\s*[:#-]?\s*$", nearby):
                found.append(self._entity("IN_DIN", m, 0.98, "regex+context"))

        found.extend(self._entity("DATE_OF_BIRTH", m, 0.99, "regex+context", "date") for m in self.DOB_RE.finditer(text))
        return found

    def _init_presidio(self) -> None:
        if self._presidio_attempted:
            return
        self._presidio_attempted = True
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            import spacy

            installed_model = next(
                (name for name in ("en_core_web_lg", "en_core_web_trf", "en_core_web_sm") if spacy.util.is_package(name)),
                None,
            )
            if installed_model is None:
                raise RuntimeError(
                    "no English spaCy model is installed; run: python -m spacy download en_core_web_sm"
                )
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": installed_model}],
                }
            )
            self._presidio = AnalyzerEngine(
                nlp_engine=provider.create_engine(), supported_languages=["en"]
            )
            self.presidio_status = f"available ({installed_model})"
        except Exception as exc:  # Presidio may be installed without a spaCy model.
            self.presidio_status = f"fallback active: {type(exc).__name__}: {exc}"

    def _presidio_entities(self, text: str) -> list[Entity]:
        self._init_presidio()
        if self._presidio is None:
            return []
        requested = ["PERSON", "LOCATION", "ORGANIZATION"]
        try:
            results = self._presidio.analyze(
                text=text,
                language="en",
                entities=requested,
                score_threshold=self.config.presidio_score_threshold,
            )
        except Exception as exc:
            self.presidio_status = f"fallback active: {type(exc).__name__}: {exc}"
            self._presidio = None
            return []

        found: list[Entity] = []
        for result in results:
            raw_type = result.entity_type.upper()
            start, end = result.start, result.end
            value = text[start:end]
            if raw_type == "PERSON":
                start, end = self._expand_person_span(text, start, end)
                value = text[start:end]
                if " " not in value.strip() and not self.config.redact_single_token_person_names:
                    continue
                entity_type = "PERSON"
            elif raw_type in {"ORGANIZATION", "ORG"}:
                if not self._valid_presidio_company(value):
                    continue
                entity_type = "COMPANY"
            elif raw_type in {"LOCATION", "LOC", "GPE"}:
                if not self._looks_like_complete_address(value):
                    continue
                entity_type = "ADDRESS"
            else:
                continue
            found.append(Entity(entity_type, start, end, result.score, "presidio", value))
        return found

    def _heuristic_entities(self, text: str) -> list[Entity]:
        found: list[Entity] = []
        for match in self.COMPANY_RE.finditer(text):
            if self._valid_company_candidate(match.group()):
                found.append(self._entity("COMPANY", match, 0.83, "company-suffix"))

        for match in self.SENSITIVE_HEADINGS_RE.finditer(text):
            value = match.group(0).strip()
            lower = value.casefold()
            entity_type = "PERSON" if "promoter" in lower or "family" in lower or "branch" in lower else "COMPANY"
            found.append(Entity(entity_type, match.start(), match.end(), 0.9, "sensitive-heading", value))

        for match in self.CONTEXTUAL_SENSITIVE_RE.finditer(text):
            value = match.group(0).strip()
            lower = value.casefold()
            entity_type = "PERSON" if "promoter" in lower or "family" in lower or "branch" in lower else "COMPANY"
            end = match.end()
            sentence_break = text.find(".", match.end())
            if sentence_break != -1:
                end = sentence_break + 1
            found.append(Entity(entity_type, match.start(), end, 0.72, "sensitive-context", text[match.start():end]))

        for match in self.ESOP_SCHEME_RE.finditer(text):
            sentence = text[max(0, match.start() - 80) : min(len(text), match.end() + 120)]
            if re.search(r"(?ix)\b(?:stock\s+option\s+(?:scheme|plan)|employee\s+stock\s+option\s+(?:scheme|plan)|esop)\b", sentence):
                value = sentence.strip()
                start = max(0, match.start() - 80)
                end = min(len(text), match.end() + 120)
                found.append(Entity("COMPANY", start, end, 0.76, "esop-title-context", value))

        family_match = self.FAMILY_BRANCH_RE.search(text)
        if family_match:
            names = re.findall(r"(?<![A-Z])([A-Z][A-Za-z'’-]+)(?=\s+Branch)", family_match.group(0))
            for name in names:
                start = text.find(name, family_match.start())
                if start != -1:
                    end = start + len(name)
                    if re.fullmatch(r"[A-Z][A-Za-z'’-]+", name):
                        found.append(Entity("PERSON", start, end, 0.7, "family-branch-context", name))

        for regex in (self.HONORIFIC_PERSON_RE, self.ROLE_PERSON_RE, self.LABELED_PERSON_RE):
            for m in regex.finditer(text):
                found.append(self._entity("PERSON", m, 0.84, "person-context", "name"))

        if re.search(r"(?i)\b(?:promoters?|directors?|key managerial personnel)\b", text):
            for m in self.ALL_CAPS_NAME_RE.finditer(text):
                value = m.group(1)
                if not self._looks_like_heading(value) and not self.COMPANY_RE.fullmatch(value):
                    start, end = m.span(1)
                    found.append(Entity("PERSON", start, end, 0.72, "all-caps-context", value))

        labeled_addresses = list(self.ADDRESS_LABEL_RE.finditer(text))
        for m in labeled_addresses:
            found.append(self._entity("ADDRESS", m, 0.9, "address-label", "address"))

        stripped = text.strip()
        if not labeled_addresses and 12 <= len(stripped) <= 240 and self.ADDRESSISH_RE.fullmatch(stripped):
            start = text.find(stripped)
            found.append(Entity("ADDRESS", start, start + len(stripped), 0.78, "address-grammar", stripped))
        return found

    def _allowlisted(self, value: str) -> bool:
        normalized = re.sub(r"\s+", " ", value).strip(" \t\r\n.,:;-—").casefold()
        return normalized in self.config.allow_list

    @classmethod
    def _valid_person_candidate(cls, value: str) -> bool:
        """Reject capitalized document terminology that statistical NER often calls a person."""
        words = re.findall(r"[A-Za-z][A-Za-z'â€™-]*", value)
        if not 2 <= len(words) <= 4:
            return False
        lowered = {word.casefold() for word in words}
        if lowered & cls.NON_PERSON_WORDS:
            return False
        if all(word.isupper() and len(word) <= 4 for word in words):
            return False
        return True

    @classmethod
    def _expand_person_span(cls, text: str, start: int, end: int) -> tuple[int, int]:
        """Recover adjacent name tokens when NER returns only a surname fragment."""
        token = r"[A-Z][A-Za-z'â€™-]*"
        blocked_titles = {"mr", "mrs", "ms", "miss", "dr", "prof"}
        while len(re.findall(token, text[start:end])) < 4:
            left = re.search(rf"(?P<word>{token})\s+$", text[:start])
            if left is None or left.group("word").casefold() in blocked_titles:
                break
            start = left.start("word")
        while len(re.findall(token, text[start:end])) < 4:
            right = re.match(rf"\s+(?P<word>{token})", text[end:])
            if right is None:
                break
            end += right.end("word")
        return start, end

    @staticmethod
    def _luhn_valid(digits: str) -> bool:
        total = 0
        parity = len(digits) % 2
        for index, char in enumerate(digits):
            value = int(char)
            if index % 2 == parity:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        return total % 10 == 0

    @staticmethod
    def _looks_like_heading(value: str) -> bool:
        heading_words = {
            "OUR PROMOTERS",
            "BOARD OF DIRECTORS",
            "CONTACT PERSON",
            "REGISTERED OFFICE",
            "CORPORATE OFFICE",
            "DETAILS OF THE OFFER",
            "RED HERRING PROSPECTUS",
        }
        return re.sub(r"\s+", " ", value).strip().upper() in heading_words

    @staticmethod
    def _looks_like_address(text: str, start: int, end: int) -> bool:
        window = text[max(0, start - 60) : min(len(text), end + 80)].casefold()
        return bool(
            re.search(
                r"\b(?:address|office|road|street|lane|building|tower|floor|plot|sector|"
                r"village|taluka|district|nagar|colony|pin|pincode)\b|\d{3}\s?\d{3}",
                window,
            )
        )

    def _valid_presidio_company(self, value: str) -> bool:
        if not self._valid_company_candidate(value):
            return False
        if self.COMPANY_RE.fullmatch(value.strip()):
            return True
        words = re.findall(r"[A-Za-z][A-Za-z&.'’-]*", value)
        normalized = re.sub(r"\s+", " ", value).strip(" .,:;-").casefold()
        if len(words) < 2 or normalized.startswith("the "):
            return False
        if normalized.endswith((" of", " and", " the", " &")):
            return False
        organizational_anchor = re.search(
            r"(?i)\b(?:bank|stock\s+exchange|insurance\s+company|mutual\s+fund|university|"
            r"hospital|authority|commission|council)\b",
            value,
        )
        return bool(organizational_anchor and (sum(1 for word in words if word[0].isupper()) >= 2 or value.isupper()))

    def _valid_company_candidate(self, value: str) -> bool:
        normalized = re.sub(r"\s+", " ", value).strip(" .,:;-—").casefold()
        if normalized in self.config.allow_list:
            return False
        generic = {
            "red herring",
            "date of birth",
            "equity shares",
            "fresh issue",
            "offer for sale",
            "social security",
            "credit card",
            "private limited",
            "public limited",
            "the bank",
            "registered office",
            "corporate office",
            "family trust",
            "bank limited",
            "refund bank",
            "escrow collection bank",
            "public offer account bank",
            "articles of association",
            "main provisions of the articles of association",
        }
        if normalized in generic:
            return False
        generic_prefixes = (
            "the offer",
            "the bid",
            "the promoter",
            "the equity",
            "the floor",
            "the designated",
            "the non-institutional",
            "the public offer",
            "the refund",
            "the sponsor",
            "the escrow",
            "the registered",
            "designated ",
            "qualified institutional",
            "retail individual",
            "non-institutional",
            "anchor investors",
            "working days",
            "asba ",
            "upi ",
            "refund ",
            "escrow collection ",
            "public offer ",
            "articles of ",
            "main provisions ",
        )
        return not normalized.startswith(generic_prefixes)

    @staticmethod
    def _looks_like_complete_address(value: str) -> bool:
        return bool(
            re.search(r"\d", value)
            and re.search(
                r"(?i)\b(?:road|street|lane|avenue|building|tower|floor|plot|sector|"
                r"village|taluka|district|nagar|colony|pin|pincode)\b",
                value,
            )
        )

    @classmethod
    def resolve_overlaps(cls, entities: Iterable[Entity]) -> list[Entity]:
        ranked = sorted(
            entities,
            key=lambda e: (
                -cls.PRECEDENCE.get(e.entity_type, 0),
                -e.length,
                -e.score,
                e.start,
            ),
        )
        accepted: list[Entity] = []
        for candidate in ranked:
            if any(candidate.start < current.end and current.start < candidate.end for current in accepted):
                continue
            accepted.append(candidate)
        return sorted(accepted, key=lambda e: (e.start, e.end))
