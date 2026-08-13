from __future__ import annotations

import io
import os
from dataclasses import dataclass
from typing import Any

from ..core.config import ImageConfig
from ..core.models import Entity
from ..detection.detector import PiiDetector
from ..replacement.pseudonymizer import DeterministicPseudonymizer
from .classifiers import ImageClassifier
from .placeholders import redacted_qr, synthetic_id, synthetic_logo


@dataclass(slots=True)
class OcrLine:
    box: list[list[float]]
    text: str
    score: float


class ImageRedactor:
    """OCRs embedded pictures, substitutes detected PII, and keeps image dimensions."""

    def __init__(
        self,
        detector: PiiDetector,
        pseudonymizer: DeterministicPseudonymizer,
        config: ImageConfig | None = None,
    ) -> None:
        self.detector = detector
        self.pseudonymizer = pseudonymizer
        self.config = config or ImageConfig()
        self.classifier = ImageClassifier(self.config)
        self._engine: Any = None
        self._engine_name = "unavailable"
        self._initialization_error = ""
        self._initialize_ocr()

    @property
    def available(self) -> bool:
        return self._engine is not None

    @property
    def status(self) -> str:
        return self._engine_name if self.available else f"unavailable: {self._initialization_error}"

    def _initialize_ocr(self) -> None:
        try:
            from rapidocr import RapidOCR

            self._engine = RapidOCR()
            self._engine_name = "RapidOCR"
            return
        except Exception as rapid_error:
            self._initialization_error = f"RapidOCR: {type(rapid_error).__name__}: {rapid_error}"

        try:
            import pytesseract

            pytesseract.get_tesseract_version()
            self._engine = pytesseract
            self._engine_name = "Tesseract"
        except Exception as tesseract_error:
            self._initialization_error += f"; Tesseract: {type(tesseract_error).__name__}: {tesseract_error}"

    def redact(self, blob: bytes, filename: str) -> tuple[bytes, list[Entity]]:
        if not self.available:
            return blob, []

        from PIL import Image, ImageDraw

        with Image.open(io.BytesIO(blob)) as opened:
            source_format = (opened.format or os.path.splitext(filename)[1].lstrip(".") or "PNG").upper()
            image = opened.convert("RGBA" if opened.mode in {"RGBA", "LA"} else "RGB")

        lines = self._ocr_lines(image)
        joined = self.classifier.joined_text(lines)
        image_kind = self.classifier.classify(image, lines)
        if image_kind:
            entity = Entity(image_kind, 0, max(1, len(joined)), 1.0, "whole-image", joined or image_kind)
            if image_kind == "ID_DOCUMENT":
                return synthetic_id(image, source_format), [entity]
            if image_kind == "COMPANY_LOGO":
                return synthetic_logo(image, source_format), [entity]
            return redacted_qr(image, source_format), [entity]

        detected: list[tuple[OcrLine, Entity]] = []
        for line in lines:
            if line.score < self.config.minimum_ocr_score or not line.text.strip():
                continue
            for entity in self.detector.analyze(line.text):
                detected.append((line, entity))

        if not detected:
            return blob, []

        draw = ImageDraw.Draw(image)
        for line, entity in detected:
            rectangle = self._entity_rectangle(line, entity)
            fill = self._sample_background(image, rectangle)
            draw.rectangle(rectangle, fill=fill)
            replacement = self.pseudonymizer.replace(entity.entity_type, entity.text)
            self._draw_fitted_text(draw, replacement, rectangle, fill)

        output = io.BytesIO()
        save_format = "JPEG" if source_format in {"JPG", "JPEG"} else source_format
        if save_format == "JPEG":
            image = image.convert("RGB")
            image.save(output, format="JPEG", quality=95, optimize=True)
        else:
            image.save(output, format=save_format)
        return output.getvalue(), [entity for _, entity in detected]

    def _ocr_lines(self, image: Any) -> list[OcrLine]:
        if self._engine_name == "RapidOCR":
            import numpy as np

            output = self._engine(np.asarray(image.convert("RGB")))
            return self._parse_rapidocr_output(output)
        return self._tesseract_lines(image)

    @staticmethod
    def _parse_rapidocr_output(output: Any) -> list[OcrLine]:
        if output is None:
            return []
        if hasattr(output, "boxes") and hasattr(output, "txts"):
            boxes = output.boxes if output.boxes is not None else []
            texts = output.txts if output.txts is not None else []
            scores = output.scores if output.scores is not None else [1.0] * len(texts)
            return [OcrLine(ImageRedactor._box_to_list(box), str(text), float(score)) for box, text, score in zip(boxes, texts, scores)]

        result = output[0] if isinstance(output, tuple) and len(output) == 2 else output
        if result is None:
            return []
        lines: list[OcrLine] = []
        for item in result:
            if len(item) < 3:
                continue
            lines.append(OcrLine(ImageRedactor._box_to_list(item[0]), str(item[1]), float(item[2])))
        return lines

    @staticmethod
    def _box_to_list(box: Any) -> list[list[float]]:
        return [[float(point[0]), float(point[1])] for point in box]

    def _tesseract_lines(self, image: Any) -> list[OcrLine]:
        from pytesseract import Output

        data = self._engine.image_to_data(image.convert("RGB"), output_type=Output.DICT)
        grouped: dict[tuple[int, int, int], list[int]] = {}
        for index, text in enumerate(data["text"]):
            if not text.strip():
                continue
            key = (data["block_num"][index], data["par_num"][index], data["line_num"][index])
            grouped.setdefault(key, []).append(index)

        lines: list[OcrLine] = []
        for indices in grouped.values():
            text = " ".join(data["text"][i] for i in indices)
            left = min(data["left"][i] for i in indices)
            top = min(data["top"][i] for i in indices)
            right = max(data["left"][i] + data["width"][i] for i in indices)
            bottom = max(data["top"][i] + data["height"][i] for i in indices)
            scores = [float(data["conf"][i]) / 100 for i in indices if float(data["conf"][i]) >= 0]
            score = sum(scores) / len(scores) if scores else 0.0
            lines.append(OcrLine([[left, top], [right, top], [right, bottom], [left, bottom]], text, score))
        return lines

    @staticmethod
    def _entity_rectangle(line: OcrLine, entity: Entity) -> tuple[int, int, int, int]:
        xs = [point[0] for point in line.box]
        ys = [point[1] for point in line.box]
        xmin, xmax = min(xs), max(xs)
        ymin, ymax = min(ys), max(ys)
        length = max(1, len(line.text))
        left = xmin + (xmax - xmin) * entity.start / length
        right = xmin + (xmax - xmin) * entity.end / length
        pad = max(1, int((ymax - ymin) * 0.08))
        return (max(0, int(left) - pad), max(0, int(ymin) - pad), int(right) + pad, int(ymax) + pad)

    @staticmethod
    def _sample_background(image: Any, rectangle: tuple[int, int, int, int]) -> tuple[int, ...]:
        from PIL import ImageStat

        x1, y1, x2, y2 = rectangle
        border = max(2, min(8, (y2 - y1) // 4))
        sample_box = (
            max(0, x1 - border),
            max(0, y1 - border),
            min(image.width, x2 + border),
            min(image.height, y2 + border),
        )
        crop = image.crop(sample_box)
        median = ImageStat.Stat(crop).median
        if image.mode == "RGBA":
            return tuple(int(v) for v in (median[:3] + [255]))
        return tuple(int(v) for v in median[:3])

    @staticmethod
    def _draw_fitted_text(draw: Any, text: str, rectangle: tuple[int, int, int, int], background: tuple[int, ...]) -> None:
        from PIL import ImageFont

        x1, y1, x2, y2 = rectangle
        width, height = max(1, x2 - x1), max(1, y2 - y1)
        font_paths = (
            "C:/Windows/Fonts/arial.ttf",
            "C:/Windows/Fonts/calibri.ttf",
            "DejaVuSans.ttf",
        )
        font = ImageFont.load_default()
        for size in range(max(8, int(height * 0.8)), 5, -1):
            candidate = None
            for path in font_paths:
                try:
                    candidate = ImageFont.truetype(path, size=size)
                    break
                except OSError:
                    continue
            if candidate is None:
                break
            bounds = draw.textbbox((0, 0), text, font=candidate)
            if bounds[2] - bounds[0] <= width and bounds[3] - bounds[1] <= height:
                font = candidate
                break
        luminance = sum(background[:3]) / 3
        if len(background) == 4:
            color = (20, 20, 20, 255) if luminance > 128 else (245, 245, 245, 255)
        else:
            color = (20, 20, 20) if luminance > 128 else (245, 245, 245)
        draw.text((x1 + 1, y1 + 1), text, fill=color, font=font)
