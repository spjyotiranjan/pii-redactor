from setuptools import find_packages, setup


setup(
    name="pii-docx-redactor",
    version="1.1.0",
    description="Layout-preserving PII pseudonymization for DOCX text and images",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "lxml>=5.3,<7",
        "Pillow>=10.4,<13",
        "presidio-analyzer>=2.2.360,<3",
        "presidio-anonymizer>=2.2.360,<3",
    ],
    extras_require={
        "ner": ["spacy>=3.8,<4"],
        "ocr": ["rapidocr>=3,<4", "onnxruntime>=1.20,<2"],
        "test": ["pytest>=8.3,<10"],
        "full": [
            "spacy>=3.8,<4",
            "rapidocr>=3,<4",
            "onnxruntime>=1.20,<2",
            "pytest>=8.3,<10",
        ],
    },
    entry_points={"console_scripts": ["pii-redact=pii_redactor.application.cli:main"]},
)
