import tempfile
import unittest
import zipfile
from pathlib import Path

from lxml import etree

from pii_redactor.core.config import DetectorConfig, PipelineConfig
from pii_redactor.document.docx_pipeline import DocxRedactionPipeline, W_NS


CONTENT_TYPES = b'''<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''

ROOT_RELS = b'''<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''

DOCUMENT = f'''<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="{W_NS}"><w:body>
  <w:p><w:r><w:t>Contact rash</w:t></w:r><w:r><w:t>i.patil@gmail.com or </w:t></w:r><w:r><w:t>+91 98765 43210</w:t></w:r></w:p>
  <w:sectPr/>
</w:body></w:document>'''.encode()


class DocxPipelineTests(unittest.TestCase):
    def test_redacts_entity_split_across_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.docx"
            output = root / "redacted.docx"
            with zipfile.ZipFile(source, "w") as package:
                package.writestr("[Content_Types].xml", CONTENT_TYPES)
                package.writestr("_rels/.rels", ROOT_RELS)
                package.writestr("word/document.xml", DOCUMENT)

            config = PipelineConfig(redact_images=False)
            config.detector = DetectorConfig(enable_presidio=False)
            report = DocxRedactionPipeline(config).redact(source, output)

            with zipfile.ZipFile(output) as package:
                xml = etree.fromstring(package.read("word/document.xml"))
                text = "".join(xml.itertext())
            self.assertNotIn("rashi.patil@gmail.com", text)
            self.assertNotIn("98765 43210", text)
            self.assertIn("@example.com", text)
            self.assertEqual(0, report.original_value_leaks)


if __name__ == "__main__":
    unittest.main()
