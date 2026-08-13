import importlib.util
import unittest

from pii_redactor.core.config import DetectorConfig
from pii_redactor.detection.detector import PiiDetector


class DetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        config = DetectorConfig(enable_presidio=False)
        self.detector = PiiDetector(config)

    def test_structured_and_contextual_entities(self) -> None:
        text = (
            "Customer: Rashi Patil, DOB: 14/02/1992, rashi.patil@gmail.com, "
            "+91 98765 43210, 4111 1111 1111 1111, 192.0.2.8"
        )
        entity_types = {entity.entity_type for entity in self.detector.analyze(text)}
        self.assertTrue(
            {"PERSON", "DATE_OF_BIRTH", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IP_ADDRESS"}
            <= entity_types
        )

    def test_order_and_ticket_numbers_are_not_pii(self) -> None:
        text = "Order 12345678 and Ticket 1234567890 were created on 10 December 2025."
        self.assertEqual([], self.detector.analyze(text))

    def test_website_with_spacing_is_detected(self) -> None:
        text = "Website: www.kshinternational. com"
        websites = [entity.text for entity in self.detector.analyze(text) if entity.entity_type == "WEBSITE"]
        self.assertEqual(["www.kshinternational. com"], websites)

    def test_financial_headings_are_not_people(self) -> None:
        text = (
            "Fresh Issue and Offer for Sale under the SEBI ICDR Regulations by Book Running Lead Managers. "
            "The weighted average cost of acquisition per Equity Share is shown below. "
            "Employee benefit expenses incurred during the year may increase."
        )
        people = [entity.text for entity in self.detector.analyze(text) if entity.entity_type == "PERSON"]
        self.assertEqual([], people)

    def test_partial_ner_name_span_expands_to_full_name(self) -> None:
        text = "Rohit Kushal Hegde*"
        start, end = self.detector._expand_person_span(text, text.index("Kushal"), text.index("Hegde") + 5)
        self.assertEqual("Rohit Kushal Hegde", text[start:end])

    def test_reporting_evaluation_module_is_removed(self) -> None:
        self.assertIsNone(importlib.util.find_spec("pii_redactor.reporting.evaluation"))


if __name__ == "__main__":
    unittest.main()
