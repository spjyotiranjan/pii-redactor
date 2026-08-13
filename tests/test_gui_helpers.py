from pathlib import Path

import pytest

from pii_redactor.application.gui import build_config_from_options


def test_build_config_from_options_enables_image_redaction_by_default():
    config = build_config_from_options("input.docx", "output.docx", image_redaction=True, enable_presidio=True)

    assert config.redact_images is True
    assert config.detector.enable_presidio is True
    assert Path("input.docx") == Path(config.input_path)
    assert Path("output.docx") == Path(config.output_path)


def test_build_config_from_options_rejects_missing_input_path():
    with pytest.raises(ValueError, match="Input DOCX"):
        build_config_from_options("", "output.docx", image_redaction=True)
