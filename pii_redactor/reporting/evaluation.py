from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.models import Entity, PipelineReport
from ..detection.detector import PiiDetector


@dataclass(frozen=True, slots=True)
class GoldEntity:
    entity_type: str
    start: int
    end: int


@dataclass(slots=True)
class EvaluationExample:
    text: str
    entities: list[GoldEntity]


def _example(text: str, labels: list[tuple[str, str]]) -> EvaluationExample:
    entities: list[GoldEntity] = []
    search_from: dict[str, int] = defaultdict(int)
    for entity_type, value in labels:
        start = text.index(value, search_from[value])
        entities.append(GoldEntity(entity_type, start, start + len(value)))
        search_from[value] = start + len(value)
    return EvaluationExample(text, entities)


def synthetic_corpus() -> list[EvaluationExample]:
    """A transparent, labeled regression corpus; it is not a claim about production accuracy."""

    return [
        _example(
            "Customer: Rashi Patil; date of birth: 14/02/1992; email rashi.patil@gmail.com; phone +91 98765 43210; website www.kshinternational. com.",
            [
                ("PERSON", "Rashi Patil"),
                ("DATE_OF_BIRTH", "14/02/1992"),
                ("EMAIL_ADDRESS", "rashi.patil@gmail.com"),
                ("PHONE_NUMBER", "+91 98765 43210"),
                ("WEBSITE", "www.kshinternational. com"),
            ],
        ),
        _example(
            "Employer: KSH International Limited. Mailing address: 42 Example Road, Pune 411 001, India.",
            [
                ("COMPANY", "KSH International Limited"),
                ("ADDRESS", "42 Example Road, Pune 411 001, India."),
            ],
        ),
        _example(
            "US SSN 123-45-6789, test card 4111 1111 1111 1111, and server 192.0.2.44.",
            [
                ("US_SSN", "123-45-6789"),
                ("CREDIT_CARD", "4111 1111 1111 1111"),
                ("IP_ADDRESS", "192.0.2.44"),
            ],
        ),
        _example(
            "PAN ABCDE1234F; GSTIN 27ABCDE1234F1Z5; CIN U12345MH2020PTC123456; DIN: 01234567.",
            [
                ("IN_PAN", "ABCDE1234F"),
                ("IN_GSTIN", "27ABCDE1234F1Z5"),
                ("IN_CIN", "U12345MH2020PTC123456"),
                ("IN_DIN", "01234567"),
            ],
        ),
        _example(
            "Order 12345678 and Ticket 1234567890 were created on 10 December 2025; these are not PII.",
            [],
        ),
    ]


def evaluate_examples(detector: PiiDetector, examples: list[EvaluationExample]) -> dict[str, Any]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    char_tp = char_tn = char_fp = char_fn = 0

    for example in examples:
        predictions = detector.analyze(example.text)
        predicted_set = {(p.entity_type, p.start, p.end) for p in predictions}
        gold_set = {(g.entity_type, g.start, g.end) for g in example.entities}

        for item in predicted_set & gold_set:
            counts[item[0]]["tp"] += 1
        for item in predicted_set - gold_set:
            counts[item[0]]["fp"] += 1
        for item in gold_set - predicted_set:
            counts[item[0]]["fn"] += 1

        gold_mask = [False] * len(example.text)
        prediction_mask = [False] * len(example.text)
        for gold in example.entities:
            gold_mask[gold.start : gold.end] = [True] * (gold.end - gold.start)
        for prediction in predictions:
            prediction_mask[prediction.start : prediction.end] = [True] * (prediction.end - prediction.start)
        for gold_value, predicted_value in zip(gold_mask, prediction_mask):
            if gold_value and predicted_value:
                char_tp += 1
            elif not gold_value and not predicted_value:
                char_tn += 1
            elif predicted_value:
                char_fp += 1
            else:
                char_fn += 1

    entity_types = sorted(set(counts) | {g.entity_type for example in examples for g in example.entities})
    per_type: dict[str, dict[str, float | int]] = {}
    totals = Counter()
    for entity_type in entity_types:
        current = counts[entity_type]
        totals.update(current)
        per_type[entity_type] = _metric_row(current["tp"], current["fp"], current["fn"])

    micro = _metric_row(totals["tp"], totals["fp"], totals["fn"])
    macro_precision = _average([float(row["precision"]) for row in per_type.values()])
    macro_recall = _average([float(row["recall"]) for row in per_type.values()])
    macro_f1 = _average([float(row["f1"]) for row in per_type.values()])
    denominator = char_tp + char_tn + char_fp + char_fn
    accuracy = (char_tp + char_tn) / denominator if denominator else 0.0

    return {
        "method": "exact entity-type and character-span comparison on the bundled labeled synthetic regression corpus",
        "limitations": (
            "These numbers validate supported formats and negative controls, not the prospectus. "
            "A manually annotated, held-out prospectus gold set is required for defensible document accuracy."
        ),
        "examples": len(examples),
        "micro": micro,
        "macro": {
            "precision": round(macro_precision, 6),
            "recall": round(macro_recall, 6),
            "f1": round(macro_f1, 6),
        },
        "character_accuracy": round(accuracy, 6),
        "character_confusion": {"tp": char_tp, "tn": char_tn, "fp": char_fp, "fn": char_fn},
        "per_entity_type": per_type,
    }


def _metric_row(tp: int, fp: int, fn: int) -> dict[str, float | int]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def _average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def load_gold_file(path: str | Path) -> list[EvaluationExample]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    examples: list[EvaluationExample] = []
    for record in payload["examples"]:
        entities = [
            GoldEntity(str(item["entity_type"]), int(item["start"]), int(item["end"]))
            for item in record["entities"]
        ]
        examples.append(EvaluationExample(str(record["text"]), entities))
    return examples


def build_evaluation_report(detector: PiiDetector, run_report: PipelineReport | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "evaluation": evaluate_examples(detector, synthetic_corpus()),
        "metric_definitions": {
            "precision": "TP / (TP + FP)",
            "recall": "TP / (TP + FN)",
            "f1": "2 * precision * recall / (precision + recall)",
            "accuracy": "(character TP + character TN) / all evaluated characters",
        },
    }
    if run_report is not None:
        report["document_run"] = run_report.to_dict()
        report["document_run_interpretation"] = (
            "Document counts and original-value leakage checks are operational QA, not ground-truth precision/recall."
        )
    return report


def save_evaluation_report(path: str | Path, report: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
