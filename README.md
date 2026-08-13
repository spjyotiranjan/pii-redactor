# PII Redaction

This project redacts personally identifiable information (PII) from DOCX files and embedded images.

It is designed for a practical document workflow:
- detects names, emails, phone numbers, company names, addresses, dates of birth, and common Indian ID formats
- replaces sensitive values with deterministic, safe pseudonyms
- removes comments and metadata that may carry hidden personal data
- optionally redacts text found in embedded images
- writes a JSON run report describing what changed

---

## How the flow works

1. Read the DOCX package
   - the project opens the Word file as a ZIP archive
   - it walks through document XML, comments, and metadata parts

2. Detect PII
   - regex, contextual checks, and optional Presidio detection are used together
   - supported patterns include emails, phone numbers, websites, dates, addresses, company names, PAN, GSTIN, CIN, DIN, SSNs, credit cards, and IP addresses

3. Replace with safe values
   - sensitive values are replaced with safe generic values such as Example Company Limited or John Doe-style forms
   - the replacement is stable within a single redaction run and does not depend on a caller-provided seed

4. Clean the document
   - comments, tracked revisions, and metadata fields are removed or sanitized

5. Process images when enabled
   - OCR is used on embedded images, and detected text is redacted if needed

6. Validate and report
   - the output DOCX is checked for integrity
   - a JSON report summarises the redaction run

---

## Project structure

- `run.py` – convenience entry point
- `pii_redactor/` – main package
  - `application/` – CLI and GUI entry points
  - `core/` – configuration and shared models
  - `detection/` – PII detection logic
  - `document/` – DOCX processing and redaction pipeline
  - `imaging/` – OCR and image redaction
  - `replacement/` – pseudonym generation
  - `reporting/` – operational report output
- `tests/` – project tests
- `output/` – generated reports and sample output

---

## Installation

Install the required dependencies:

```bash
python -m pip install -r requirements.txt
```

Install the project itself for CLI and GUI command access:

```bash
python -m pip install -e .
```

This keeps the project install simple while still including OCR, detection, and GUI dependencies.

---

## GUI usage

Launch the desktop app after installing dependencies:

```bash
python -m pii_redactor.application.gui
```

Or use the installed command:

```bash
pii-redact-gui
```

The GUI lets you:
- choose an input DOCX file
- pick an output folder
- run redaction with optional image and Presidio toggles

---

## CLI usage

This tool scans a DOCX file, finds sensitive personal and business information, and writes a cleaned version with those values replaced by safe generic placeholders. It also removes hidden metadata and comments that may contain private details, and can optionally redact text found inside embedded images.

After installation, the command is available as `pii-redact`.

You can also run it directly with Python:

```bash
python -m pii_redactor --help
```

### 1) Redact a DOCX file

```bash
python -m pii_redactor redact input.docx output.docx
```

### 2) Save a run report

```bash
python -m pii_redactor redact input.docx output.docx --run-report output/run_report.json
```

This writes a JSON report with counts and warnings for the redaction run.

### 3) Disable image redaction

Use this when you want to redact only the DOCX text and skip OCR-based image processing.

```bash
python -m pii_redactor redact input.docx output.docx --no-images
```

### 4) Disable Presidio

Use this when you want to skip the optional Presidio NLP detector and rely only on the built-in regex and heuristic detection rules.

```bash
python -m pii_redactor redact input.docx output.docx --no-presidio
```

---

## Example workflow

```bash
python -m pii_redactor redact sample.docx redacted_output.docx --run-report output/run_report.json
```

This will:
1. read the source DOCX
2. detect and replace sensitive values
3. sanitize metadata and comments
4. process images if enabled
5. validate the output DOCX
6. write a JSON report

---

## Supported sensitive types

The project focuses on common document PII and corporate identifiers, including:
- names and person references
- email addresses
- phone numbers
- websites
- company names
- addresses
- dates of birth
- PAN, GSTIN, CIN, DIN, Aadhaar-style values
- SSNs and credit card numbers
- IP addresses

---

## Quick commands summary

```bash
# install dependencies
python -m pip install -r requirements.txt

# install the package
python -m pip install -e .

# launch GUI
python -m pii_redactor.application.gui

# or use the installed GUI command
pii-redact-gui

# redact a document from the terminal
python -m pii_redactor redact input.docx output.docx

# redact and save a report
python -m pii_redactor redact input.docx output.docx --run-report output/run_report.json
```

---

## Need help?

Run:

```bash
python -m pii_redactor explain
```

This prints a beginner-friendly map of the project structure and the redaction pipeline.
