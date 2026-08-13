from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from tkinter import filedialog, messagebox, ttk

from ..core.config import PipelineConfig
from ..document.docx_pipeline import DocxRedactionPipeline


@dataclass
class GUIJobConfig:
    input_path: str
    output_path: str
    redact_images: bool = True
    enable_presidio: bool = True

    def __post_init__(self) -> None:
        if not self.input_path.strip():
            raise ValueError("Input DOCX path is required.")
        if not self.output_path.strip():
            raise ValueError("Output path is required.")
        self.detector = SimpleNamespace(enable_presidio=self.enable_presidio)

    def to_pipeline_config(self) -> PipelineConfig:
        config = PipelineConfig(redact_images=self.redact_images)
        config.detector.enable_presidio = self.enable_presidio
        return config


def build_config_from_options(
    input_path: str,
    output_path: str,
    *,
    image_redaction: bool = True,
    enable_presidio: bool = True,
) -> GUIJobConfig:
    if not input_path or not str(input_path).strip():
        raise ValueError("Input DOCX path is required.")
    if not output_path or not str(output_path).strip():
        raise ValueError("Output path is required.")

    return GUIJobConfig(
        input_path=str(input_path),
        output_path=str(output_path),
        redact_images=image_redaction,
        enable_presidio=enable_presidio,
    )


def process_document(job: GUIJobConfig) -> Path:
    source_path = Path(job.input_path).expanduser().resolve()
    destination = Path(job.output_path).expanduser().resolve()

    if not source_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {source_path}")
    if source_path.suffix.lower() != ".docx":
        raise ValueError("Input file must be a .docx file.")

    if destination.exists() and destination.is_dir():
        filename = f"{source_path.stem}_redacted.docx"
        destination = destination / filename
    elif destination.exists() and destination.is_file():
        if destination.suffix.lower() != ".docx":
            raise ValueError("Output file must end with .docx")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.suffix.lower() != ".docx":
            destination = destination.with_suffix(".docx")

    config = job.to_pipeline_config()
    pipeline = DocxRedactionPipeline(config)
    report = pipeline.redact(source_path, destination)

    if report.original_value_leaks:
        raise RuntimeError(
            "Redaction finished, but the audit detected original values still present. Review the output carefully."
        )

    return destination


class RedactionApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("PII Redaction")
        self.root.geometry("620x320")
        self.root.minsize(560, 300)

        self.input_path = tk.StringVar()
        self.output_dir = tk.StringVar()
        self.image_redaction = tk.BooleanVar(value=True)
        self.enable_presidio = tk.BooleanVar(value=True)

        main = ttk.Frame(root, padding=14)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="Input DOCX:").grid(row=0, column=0, sticky="w", pady=(0, 6))
        ttk.Entry(main, textvariable=self.input_path, width=60).grid(row=0, column=1, sticky="ew", padx=(10, 8))
        ttk.Button(main, text="Browse", command=self.choose_input).grid(row=0, column=2, sticky="ew")

        ttk.Label(main, text="Output folder:").grid(row=1, column=0, sticky="w", pady=(8, 6))
        ttk.Entry(main, textvariable=self.output_dir, width=60).grid(row=1, column=1, sticky="ew", padx=(10, 8))
        ttk.Button(main, text="Browse", command=self.choose_output_folder).grid(row=1, column=2, sticky="ew")

        ttk.Checkbutton(main, text="Enable image redaction", variable=self.image_redaction).grid(
            row=2, column=1, sticky="w", padx=(10, 0), pady=(8, 6)
        )
        ttk.Checkbutton(main, text="Enable Presidio NER", variable=self.enable_presidio).grid(
            row=3, column=1, sticky="w", padx=(10, 0), pady=(0, 10)
        )

        ttk.Button(main, text="Process document", command=self.process).grid(
            row=4, column=1, sticky="ew", padx=(10, 0), pady=(6, 8)
        )

        self.status = ttk.Label(main, text="Ready", foreground="#1f3b5d")
        self.status.grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 0))

        main.columnconfigure(1, weight=1)

    def choose_input(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select DOCX file",
            filetypes=[("Word documents", "*.docx"), ("All files", "*.*")],
        )
        if file_path:
            self.input_path.set(file_path)

    def choose_output_folder(self) -> None:
        folder = filedialog.askdirectory(title="Choose output folder")
        if folder:
            self.output_dir.set(folder)

    def process(self) -> None:
        input_value = self.input_path.get().strip()
        output_value = self.output_dir.get().strip()

        if not input_value:
            messagebox.showerror("Missing input", "Please choose an input DOCX file.")
            return

        if not output_value:
            messagebox.showerror("Missing output folder", "Please choose an output folder.")
            return

        try:
            self.status.configure(text="Processing...")
            self.status.update_idletasks()

            config = build_config_from_options(
                input_value,
                output_value,
                image_redaction=self.image_redaction.get(),
                enable_presidio=self.enable_presidio.get(),
            )
            destination = process_document(config)

            messagebox.showinfo(
                "Completed",
                f"Redacted document saved to:\n{destination}",
            )
            self.status.configure(text=f"Saved: {destination}")
        except Exception as exc:  # pragma: no cover - UI error path
            messagebox.showerror("Processing failed", str(exc))
            self.status.configure(text=f"Error: {exc}")


def main() -> None:
    root = tk.Tk()
    RedactionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
