from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.config import PipelineConfig
from ..detection.detector import PiiDetector
from ..document.docx_pipeline import DocxRedactionPipeline
from ..reporting.evaluation import (
    build_evaluation_report,
    evaluate_examples,
    load_gold_file,
    save_evaluation_report,
)


WALKTHROUGH = """
core/ contains configuration and shared data models.
detection/ finds PII with regex, checksums, Presidio NER, contextual rules, and overlap resolution.
replacement/ maps detected values to obvious templates such as John Doe and Example Company Limited.
imaging/ classifies logos, identity cards, and QR codes, then creates safe replacements or redacts OCR text.
document/ edits DOCX text across Word runs, processes all embedded media, scrubs metadata, and validates the output.
reporting/ calculates exact-span precision, recall, F1, and character accuracy.
application/ provides the redact, evaluate, and explain command-line commands.
""".strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pii-redact", description="Pseudonymize PII in DOCX text and images")
    subparsers = parser.add_subparsers(dest="command", required=True)

    redact = subparsers.add_parser("redact", help="Create a redacted DOCX")
    redact.add_argument("input", type=Path)
    redact.add_argument("output", type=Path)
    redact.add_argument("--run-report", type=Path, help="Write privacy-safe operational counts as JSON")
    redact.add_argument("--evaluation-report", type=Path, help="Write metrics and run results as JSON")
    redact.add_argument("--seed", default="pii-redaction-assignment-v1")
    redact.add_argument("--no-images", action="store_true")
    redact.add_argument("--no-presidio", action="store_true")

    evaluate = subparsers.add_parser("evaluate", help="Evaluate detection with synthetic or supplied gold annotations")
    evaluate.add_argument("--gold", type=Path)
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument("--no-presidio", action="store_true")

    subparsers.add_parser("explain", help="Print a beginner-friendly source-code map")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "explain":
        print(WALKTHROUGH)
        return 0

    if args.command == "redact":
        config = PipelineConfig(seed=args.seed, redact_images=not args.no_images)
        config.detector.enable_presidio = not args.no_presidio
        pipeline = DocxRedactionPipeline(config)
        run_report = pipeline.redact(args.input, args.output, args.run_report)
        evaluation = build_evaluation_report(pipeline.detector, run_report)
        if args.evaluation_report:
            save_evaluation_report(args.evaluation_report, evaluation)
        print(json.dumps(evaluation, indent=2))
        return 0 if run_report.original_value_leaks == 0 else 2

    detector = PiiDetector()
    detector.config.enable_presidio = not args.no_presidio
    examples = load_gold_file(args.gold) if args.gold else None
    report = (
        {"evaluation": evaluate_examples(detector, examples)}
        if examples is not None
        else build_evaluation_report(detector)
    )
    if args.output:
        save_evaluation_report(args.output, report)
    print(json.dumps(report, indent=2))
    return 0
