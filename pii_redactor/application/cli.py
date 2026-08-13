from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.config import PipelineConfig
from ..document.docx_pipeline import DocxRedactionPipeline


WALKTHROUGH = """
core/ contains configuration and shared data models.
detection/ finds PII with regex, checksums, Presidio NER, contextual rules, and overlap resolution.
replacement/ maps detected values to obvious templates such as John Doe and Example Company Limited.
imaging/ classifies logos, identity cards, and QR codes, then creates safe replacements or redacts OCR text.
document/ edits DOCX text across Word runs, processes all embedded media, scrubs metadata, and validates the output.
reporting/ summarizes the redaction run with counts, warnings, and leak checks.
application/ provides the redact and explain command-line commands.
""".strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pii-redact", description="Pseudonymize PII in DOCX text and images")
    subparsers = parser.add_subparsers(dest="command", required=True)

    redact = subparsers.add_parser("redact", help="Create a redacted DOCX")
    redact.add_argument("input", type=Path)
    redact.add_argument("output", type=Path)
    redact.add_argument("--run-report", type=Path, help="Write privacy-safe operational counts as JSON")
    redact.add_argument("--no-images", action="store_true")
    redact.add_argument("--no-presidio", action="store_true")

    subparsers.add_parser("explain", help="Print a beginner-friendly source-code map")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "explain":
        print(WALKTHROUGH)
        return 0

    if args.command == "redact":
        config = PipelineConfig(redact_images=not args.no_images)
        config.detector.enable_presidio = not args.no_presidio
        pipeline = DocxRedactionPipeline(config)
        run_report = pipeline.redact(args.input, args.output, args.run_report)
        print(json.dumps(run_report.to_dict(), indent=2))
        return 0 if run_report.original_value_leaks == 0 else 2

    return 0
