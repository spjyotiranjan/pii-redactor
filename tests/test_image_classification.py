import unittest
from types import SimpleNamespace

from PIL import Image

from pii_redactor.core.config import ImageConfig
from pii_redactor.imaging.classifiers import ImageClassifier
from pii_redactor.imaging.placeholders import synthetic_logo


class ImageClassificationTests(unittest.TestCase):
    def test_icici_text_is_classified_as_company_logo(self) -> None:
        image = Image.new("RGB", (260, 53), "white")
        lines = [SimpleNamespace(text="ICICI Securities", score=0.98)]
        classifier = ImageClassifier(ImageConfig())
        self.assertEqual("COMPANY_LOGO", classifier.classify(image, lines))

    def test_company_logo_is_replaced_at_same_dimensions(self) -> None:
        from io import BytesIO

        image = Image.new("RGB", (260, 53), "white")
        result = synthetic_logo(image, "PNG")
        with Image.open(BytesIO(result)) as replacement:
            self.assertEqual(image.size, replacement.size)
            self.assertNotEqual(result, self._image_bytes(image))

    @staticmethod
    def _image_bytes(image: Image.Image) -> bytes:
        from io import BytesIO

        output = BytesIO()
        image.save(output, format="PNG")
        return output.getvalue()


if __name__ == "__main__":
    unittest.main()
