from __future__ import annotations

import io
from typing import Any


def synthetic_logo(image: Any, source_format: str) -> bytes:
    """Replace a real company mark with a neutral, clearly synthetic mark."""
    from PIL import Image, ImageDraw, ImageFont

    width, height = image.size
    replacement = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(replacement)
    accent = (45, 92, 145)
    margin = max(2, min(width, height) // 12)
    icon_size = max(8, min(height - 2 * margin, width // 5))
    draw.rounded_rectangle(
        (margin, margin, margin + icon_size, margin + icon_size),
        radius=max(2, icon_size // 5),
        fill=accent,
    )
    draw.text(
        (margin + icon_size // 4, margin + icon_size // 8),
        "E",
        fill="white",
        font=_font(ImageFont, max(8, int(icon_size * 0.65)), bold=True),
    )

    text = "EXAMPLE COMPANY"
    available_width = max(1, width - (margin * 3 + icon_size))
    font = _fit_font(draw, ImageFont, text, available_width, max(8, height - 2 * margin), bold=True)
    bounds = draw.textbbox((0, 0), text, font=font)
    text_height = bounds[3] - bounds[1]
    draw.text(
        (margin * 2 + icon_size, max(margin, (height - text_height) // 2 - bounds[1])),
        text,
        fill=(30, 42, 55),
        font=font,
    )
    return _save(replacement, source_format)


def synthetic_id(image: Any, source_format: str) -> bytes:
    """Replace a photographed identity document with a fully synthetic card."""
    from PIL import Image, ImageDraw, ImageFont

    width, height = image.size
    replacement = Image.new("RGB", (width, height), (225, 239, 245))
    draw = ImageDraw.Draw(replacement)
    title_font = _font(ImageFont, max(18, height // 18), bold=True)
    body_font = _font(ImageFont, max(13, height // 30))
    x = max(18, width // 14)
    y = max(18, height // 12)
    draw.text((x, y), "SYNTHETIC ID DOCUMENT", fill=(24, 67, 91), font=title_font)
    y += title_font.size * 2
    values = (
        "Name: John Doe",
        "Identifier: TEST-0000-0000",
        "Date of birth: 01 January 1990",
        "Address: 123 Example Street, Sample City",
    )
    for value in values:
        draw.text((x, y), value, fill=(20, 20, 20), font=body_font)
        y += int(body_font.size * 1.7)
    return _save(replacement, source_format)


def redacted_qr(image: Any, source_format: str) -> bytes:
    """Replace a QR code because it may contain invisible identifiers or links."""
    from PIL import Image, ImageDraw, ImageFont

    width, height = image.size
    replacement = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(replacement)
    inset = max(3, min(width, height) // 10)
    draw.rectangle((inset, inset, width - inset, height - inset), fill=(235, 238, 242))
    draw.line((inset, inset, width - inset, height - inset), fill=(150, 35, 35), width=max(2, inset // 3))
    draw.line((width - inset, inset, inset, height - inset), fill=(150, 35, 35), width=max(2, inset // 3))
    text = "QR REDACTED"
    font = _fit_font(draw, ImageFont, text, width - 2 * inset, max(8, height // 4), bold=True)
    bounds = draw.textbbox((0, 0), text, font=font)
    draw.rectangle((0, height - (bounds[3] - bounds[1]) - 4, width, height), fill="white")
    draw.text(((width - (bounds[2] - bounds[0])) // 2, height - (bounds[3] - bounds[1]) - 3), text, fill=(90, 20, 20), font=font)
    return _save(replacement, source_format)


def _fit_font(draw: Any, image_font: Any, text: str, width: int, height: int, bold: bool = False) -> Any:
    for size in range(max(8, height), 5, -1):
        font = _font(image_font, size, bold)
        bounds = draw.textbbox((0, 0), text, font=font)
        if bounds[2] - bounds[0] <= width and bounds[3] - bounds[1] <= height:
            return font
    return image_font.load_default()


def _font(image_font: Any, size: int, bold: bool = False) -> Any:
    paths = (
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/calibrib.ttf" if bold else "C:/Windows/Fonts/calibri.ttf",
        "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf",
    )
    for path in paths:
        try:
            return image_font.truetype(path, size=size)
        except OSError:
            continue
    return image_font.load_default()


def _save(image: Any, source_format: str) -> bytes:
    output = io.BytesIO()
    save_format = "JPEG" if source_format in {"JPG", "JPEG"} else source_format
    if save_format == "JPEG":
        image.convert("RGB").save(output, format="JPEG", quality=95, optimize=True)
    else:
        image.save(output, format=save_format)
    return output.getvalue()
