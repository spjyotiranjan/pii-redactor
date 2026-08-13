"""PII redaction package for Word documents."""

from .core.config import PipelineConfig
from .document.docx_pipeline import DocxRedactionPipeline

__all__ = ["DocxRedactionPipeline", "PipelineConfig"]
__version__ = "1.1.0"
