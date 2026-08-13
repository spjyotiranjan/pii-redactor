from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from lxml import etree

from .config import PipelineConfig
from .detector import PiiDetector
from .image_pipeline import ImageRedactor
from .models import Entity, PipelineReport
from .pseudonymizer import DeterministicPseudonymizer


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
XML_NS = "http://www.w3.org/XML/1998/namespace"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
NS = {"w": W_NS, "a": A_NS}


class DocxRedactionPipeline:
    """Rewrites DOCX package parts while preserving styles, runs, relationships, and geometry."""

    STORY_PART_RE = re.compile(
        r"^word/(?:document|header\d+|footer\d+|footnotes|endnotes|comments|glossary/document)\.xml$"
    )
    IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"}

    def __init__(self, config: PipelineConfig | None = None) -> None:
        self.config = config or PipelineConfig()
        self.detector = PiiDetector(self.config.detector)
        self.pseudonymizer = DeterministicPseudonymizer()
        self.image_redactor = ImageRedactor(self.detector, self.pseudonymizer)

    def redact(self, input_path: str | Path, output_path: str | Path, report_path: str | Path | None = None) -> PipelineReport:
        source = Path(input_path).resolve()
        destination = Path(output_path).resolve()
        if not source.exists():
            raise FileNotFoundError(source)
        if source.suffix.casefold() != ".docx":
            raise ValueError("Input must be a .docx file")
        if source == destination:
            raise ValueError("Output must differ from input so the original remains recoverable")
        destination.parent.mkdir(parents=True, exist_ok=True)

        report = PipelineReport(str(source), str(destination))
        if self.config.redact_images and not self.image_redactor.available:
            report.warnings.append(f"Embedded-image OCR skipped because OCR is {self.image_redactor.status}")

        file_descriptor, temporary_name = tempfile.mkstemp(
            suffix=".docx", prefix=f".{destination.stem}-", dir=destination.parent
        )
        os.close(file_descriptor)
        temporary_path = Path(temporary_name)
        try:
            self._rewrite_package(source, temporary_path, report)
            self._run_global_consistency_pass(temporary_path, report)
            self._validate_docx(temporary_path)
            try:
                os.replace(temporary_path, destination)
            except PermissionError:
                with temporary_path.open("rb") as source_stream, destination.open("wb") as destination_stream:
                    shutil.copyfileobj(source_stream, destination_stream, length=1024 * 1024)
                temporary_path.unlink()
        finally:
            if temporary_path.exists():
                temporary_path.unlink()

        report.original_value_leaks = self._count_original_leaks(destination)
        if report.original_value_leaks:
            report.warnings.append(
                f"Leak audit found {report.original_value_leaks} original detected value occurrence(s); review before sharing."
            )
        if not self.detector.presidio_status.startswith("available"):
            report.warnings.append(f"Presidio NER {self.detector.presidio_status}; deterministic recognizers and heuristics were used.")

        if report_path is not None:
            path = Path(report_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        return report

    def _run_global_consistency_pass(self, path: Path, report: PipelineReport) -> None:
        """Replace known values everywhere, including occurrences whose local context was weak."""
        items = self.pseudonymizer.original_items
        if not items:
            return
        patterns: list[tuple[str, re.Pattern[str]]] = []
        for entity_type, original in items:
            if len(original.strip()) < 4:
                continue
            pieces = [re.escape(piece) for piece in re.split(r"\s+", original.strip()) if piece]
            if not pieces:
                continue
            patterns.append((entity_type, re.compile(r"\s+".join(pieces), re.IGNORECASE)))

        file_descriptor, second_name = tempfile.mkstemp(suffix=".docx", prefix=f".{path.stem}-pass2-", dir=path.parent)
        os.close(file_descriptor)
        second_path = Path(second_name)
        try:
            with zipfile.ZipFile(path, "r") as input_zip, zipfile.ZipFile(
                second_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
            ) as output_zip:
                for info in input_zip.infolist():
                    blob = input_zip.read(info.filename)
                    if info.filename.endswith((".xml", ".rels")):
                        try:
                            blob = self._replace_known_values_in_xml(blob, patterns, report)
                        except etree.XMLSyntaxError:
                            pass
                    output_zip.writestr(info, blob)
            os.replace(second_path, path)
        finally:
            if second_path.exists():
                second_path.unlink()

    def _replace_known_values_in_xml(
        self, blob: bytes, patterns: list[tuple[str, re.Pattern[str]]], report: PipelineReport
    ) -> bytes:
        root = etree.fromstring(blob, parser=etree.XMLParser(resolve_entities=False, remove_blank_text=False))
        for paragraph in root.xpath(".//w:p", namespaces=NS):
            nodes = paragraph.xpath(".//w:t | .//w:instrText", namespaces=NS)
            if nodes:
                entities = self._known_entities("".join(node.text or "" for node in nodes), patterns)
                for entity in reversed(entities):
                    replacement = self.pseudonymizer.replace(entity.entity_type, entity.text)
                    self._replace_span(nodes, entity.start, entity.end, replacement)
                self._record_entities(report, entities, "known-value")

        for paragraph in root.xpath(".//a:p", namespaces=NS):
            nodes = paragraph.xpath(".//a:t", namespaces=NS)
            if nodes:
                entities = self._known_entities("".join(node.text or "" for node in nodes), patterns)
                for entity in reversed(entities):
                    replacement = self.pseudonymizer.replace(entity.entity_type, entity.text)
                    self._replace_span(nodes, entity.start, entity.end, replacement)
                self._record_entities(report, entities, "known-value")

        orphan_text_nodes = root.xpath(
            ".//*[local-name()='t' or local-name()='instrText']"
            "[not(ancestor::w:p) and not(ancestor::a:p)]",
            namespaces=NS,
        )
        for element in orphan_text_nodes:
            if element.text:
                element.text, entities = self._replace_known_value_string(element.text, patterns)
                self._record_entities(report, entities, "known-value")

        safe_attribute_names = {"Target", "descr", "description", "title", "name", "alt"}
        for element in root.iter():
            for attribute, value in list(element.attrib.items()):
                if etree.QName(attribute).localname not in safe_attribute_names:
                    continue
                new_value, entities = self._replace_known_value_string(value, patterns)
                if entities:
                    element.set(attribute, new_value)
                    self._record_entities(report, entities, "known-value")
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=None)

    def _replace_known_value_string(
        self, value: str, patterns: list[tuple[str, re.Pattern[str]]]
    ) -> tuple[str, list[Entity]]:
        entities = self._known_entities(value, patterns)
        output = value
        for entity in reversed(entities):
            replacement = self.pseudonymizer.replace(entity.entity_type, entity.text)
            output = output[: entity.start] + replacement + output[entity.end :]
        return output, entities

    def _known_entities(self, value: str, patterns: list[tuple[str, re.Pattern[str]]]) -> list[Entity]:
        candidates: list[Entity] = []
        for entity_type, pattern in patterns:
            for match in pattern.finditer(value):
                candidates.append(
                    Entity(entity_type, match.start(), match.end(), 1.0, "known-value", match.group())
                )
        return self.detector.resolve_overlaps(candidates)

    def _rewrite_package(self, source: Path, destination: Path, report: PipelineReport) -> None:
        with zipfile.ZipFile(source, "r") as input_zip, zipfile.ZipFile(
            destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as output_zip:
            for info in input_zip.infolist():
                name = info.filename
                if self._should_drop_part(name):
                    continue
                blob = input_zip.read(name)
                try:
                    if name.endswith((".xml", ".rels")):
                        blob = self._process_xml_part(name, blob, report)
                    elif (
                        self.config.redact_images
                        and name.startswith("word/media/")
                        and Path(name).suffix.casefold() in self.IMAGE_EXTENSIONS
                    ):
                        report.processed_images += 1
                        blob, entities = self.image_redactor.redact(blob, name)
                        if entities:
                            report.images_with_redactions += 1
                            self._record_entities(report, entities, "image")
                except Exception as exc:
                    report.warnings.append(f"Could not process {name}: {type(exc).__name__}: {exc}")
                output_zip.writestr(info, blob)

    def _should_drop_part(self, name: str) -> bool:
        if self.config.remove_comments and (
            name == "word/comments.xml"
            or name.startswith("word/commentsExtended")
            or name.startswith("word/people.xml")
        ):
            return True
        if self.config.scrub_metadata and name == "docProps/custom.xml":
            return True
        return False

    def _process_xml_part(self, name: str, blob: bytes, report: PipelineReport) -> bytes:
        parser = etree.XMLParser(resolve_entities=False, remove_blank_text=False, recover=False)
        root = etree.fromstring(blob, parser=parser)

        self._scrub_revision_ids(root)
        if self.config.scrub_metadata:
            self._scrub_metadata_part(name, root, report)
        if self.config.remove_comments:
            self._remove_comment_markup(name, root, report)
        if self.config.remove_tracked_deletions and self.STORY_PART_RE.match(name):
            self._remove_tracked_deletions(root)

        if self.STORY_PART_RE.match(name):
            report.processed_story_parts += 1
            paragraphs = root.xpath(".//w:p", namespaces=NS)
            for paragraph in paragraphs:
                nodes = paragraph.xpath(".//w:t | .//w:instrText", namespaces=NS)
                if not nodes:
                    continue
                report.processed_paragraphs += 1
                entities = self._replace_text_nodes(nodes)
                self._record_entities(report, entities, "text")

            orphan_nodes = root.xpath(
                ".//w:t[not(ancestor::w:p)] | .//w:instrText[not(ancestor::w:p)]", namespaces=NS
            )
            for node in orphan_nodes:
                entities = self._replace_text_nodes([node])
                self._record_entities(report, entities, "text")

        for paragraph in root.xpath(".//a:p", namespaces=NS):
            nodes = paragraph.xpath(".//a:t", namespaces=NS)
            if nodes:
                entities = self._replace_text_nodes(nodes)
                self._record_entities(report, entities, "drawing-text")

        for node in root.xpath(".//a:t[not(ancestor::a:p)]", namespaces=NS):
            entities = self._replace_text_nodes([node])
            self._record_entities(report, entities, "drawing-text")

        self._redact_relationship_targets(root, report)
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=None)

    def _replace_text_nodes(self, nodes: list[Any]) -> list[Entity]:
        text = "".join(node.text or "" for node in nodes)
        entities = self.detector.analyze(text)
        for entity in reversed(entities):
            replacement = self.pseudonymizer.replace(entity.entity_type, entity.text)
            self._replace_span(nodes, entity.start, entity.end, replacement)
        for node in nodes:
            value = node.text or ""
            xml_space = f"{{{XML_NS}}}space"
            if value.startswith(" ") or value.endswith(" "):
                node.set(xml_space, "preserve")
            elif xml_space in node.attrib:
                del node.attrib[xml_space]
        return entities

    @staticmethod
    def _replace_span(nodes: list[Any], start: int, end: int, replacement: str) -> None:
        positions: list[tuple[int, int]] = []
        cursor = 0
        for node in nodes:
            value = node.text or ""
            positions.append((cursor, cursor + len(value)))
            cursor += len(value)

        start_index = end_index = None
        for index, (node_start, node_end) in enumerate(positions):
            if start_index is None and node_start <= start < node_end:
                start_index = index
            if node_start < end <= node_end:
                end_index = index
                break
        if start_index is None or end_index is None:
            raise ValueError(f"Span {start}:{end} is outside text-node boundaries")

        start_node = nodes[start_index]
        end_node = nodes[end_index]
        start_local = start - positions[start_index][0]
        end_local = end - positions[end_index][0]
        if start_index == end_index:
            value = start_node.text or ""
            start_node.text = value[:start_local] + replacement + value[end_local:]
            return

        start_value = start_node.text or ""
        end_value = end_node.text or ""
        start_node.text = start_value[:start_local] + replacement
        for index in range(start_index + 1, end_index):
            nodes[index].text = ""
        end_node.text = end_value[end_local:]

    @staticmethod
    def _record_entities(report: PipelineReport, entities: list[Entity], surface: str) -> None:
        for entity in entities:
            report.detected_by_type[entity.entity_type] += 1
            report.replacements_by_surface[surface] += 1

    def _redact_relationship_targets(self, root: Any, report: PipelineReport) -> None:
        if root.tag != f"{{{REL_NS}}}Relationships":
            return
        for relationship in list(root):
            rel_type = relationship.get("Type", "")
            if self.config.remove_comments and ("comments" in rel_type or rel_type.endswith("/person")):
                root.remove(relationship)
                continue
            if self.config.scrub_metadata and rel_type.endswith("/custom-properties"):
                root.remove(relationship)
                continue
            target = relationship.get("Target", "")
            entities = self.detector.analyze(target)
            if not entities:
                continue
            value = target
            for entity in reversed(entities):
                replacement = self.pseudonymizer.replace(entity.entity_type, entity.text)
                value = value[: entity.start] + replacement + value[entity.end :]
            relationship.set("Target", value)
            self._record_entities(report, entities, "relationship")

    @staticmethod
    def _scrub_revision_ids(root: Any) -> None:
        for element in root.iter():
            for attribute in list(element.attrib):
                local_name = etree.QName(attribute).localname
                if local_name.startswith("rsid"):
                    del element.attrib[attribute]

    @staticmethod
    def _scrub_metadata_part(name: str, root: Any, report: PipelineReport) -> None:
        if name == "docProps/core.xml":
            sensitive = {"creator", "lastModifiedBy", "lastPrinted"}
            for element in root.iter():
                if etree.QName(element).localname in sensitive:
                    element.text = ""
            report.metadata_scrubbed = True
        elif name == "docProps/app.xml":
            for element in root.iter():
                if etree.QName(element).localname in {"Manager", "Company"}:
                    element.text = ""
        elif name == "[Content_Types].xml":
            for element in list(root):
                part_name = element.get("PartName", "")
                if part_name in {"/docProps/custom.xml", "/word/comments.xml"} or "commentsExtended" in part_name:
                    root.remove(element)

    @staticmethod
    def _remove_comment_markup(name: str, root: Any, report: PipelineReport) -> None:
        if not name.startswith("word/"):
            return
        removed = False
        comment_tags = {
            f"{{{W_NS}}}commentRangeStart",
            f"{{{W_NS}}}commentRangeEnd",
            f"{{{W_NS}}}commentReference",
        }
        for element in list(root.iter()):
            if element.tag in comment_tags and element.getparent() is not None:
                element.getparent().remove(element)
                removed = True
        if removed or name == "word/document.xml":
            report.comments_removed = True

    @staticmethod
    def _remove_tracked_deletions(root: Any) -> None:
        for deletion in root.xpath(".//w:del", namespaces=NS):
            parent = deletion.getparent()
            if parent is not None:
                parent.remove(deletion)

    @staticmethod
    def _validate_docx(path: Path) -> None:
        with zipfile.ZipFile(path, "r") as package:
            bad_entry = package.testzip()
            if bad_entry:
                raise ValueError(f"Corrupt ZIP entry: {bad_entry}")
            required = {"[Content_Types].xml", "_rels/.rels", "word/document.xml"}
            missing = required.difference(package.namelist())
            if missing:
                raise ValueError(f"Invalid DOCX; missing: {', '.join(sorted(missing))}")
            etree.fromstring(package.read("word/document.xml"))

    def _count_original_leaks(self, output_path: Path) -> int:
        searchable_text: list[str] = []
        searchable_digits: list[str] = []
        with zipfile.ZipFile(output_path, "r") as package:
            for name in package.namelist():
                if not name.endswith((".xml", ".rels")):
                    continue
                try:
                    root = etree.fromstring(package.read(name))
                except etree.XMLSyntaxError:
                    continue
                for paragraph in root.xpath(".//*[local-name()='p']"):
                    text_nodes = paragraph.xpath(
                        ".//*[local-name()='t' or local-name()='instrText']"
                    )
                    value = "".join(node.text or "" for node in text_nodes)
                    if value:
                        searchable_text.append(value)
                for element in root.iter():
                    for attribute, value in element.attrib.items():
                        if etree.QName(attribute).localname in {
                            "Target",
                            "descr",
                            "description",
                            "title",
                            "name",
                            "alt",
                        }:
                            searchable_text.append(str(value))

        text_segments = [re.sub(r"\s+", " ", value).casefold() for value in searchable_text]
        digit_segments = [re.sub(r"\D", "", value) for value in searchable_text]
        leaks = 0
        digit_types = {"PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IN_AADHAAR", "IN_DIN"}
        for entity_type, original in self.pseudonymizer.original_items:
            if entity_type in digit_types:
                needle = re.sub(r"\D", "", original)
                if len(needle) >= 7 and any(needle in segment for segment in digit_segments):
                    leaks += 1
            else:
                needle = re.sub(r"\s+", " ", original).strip().casefold()
                if len(needle) >= 4 and any(needle in segment for segment in text_segments):
                    leaks += 1
        return leaks
