import re
import unittest

from pii_redactor.replacement.pseudonymizer import DeterministicPseudonymizer


class PseudonymizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pseudonymizer = DeterministicPseudonymizer("test-seed")

    def test_mapping_is_stable_and_different(self) -> None:
        first = self.pseudonymizer.replace("PERSON", "Rashi Patil")
        second = self.pseudonymizer.replace("PERSON", "Rashi   Patil")
        self.assertEqual(first, second)
        self.assertNotEqual("Rashi Patil", first)

    def test_phone_format_is_preserved(self) -> None:
        fake = self.pseudonymizer.replace("PHONE_NUMBER", "+91 98765 43210")
        self.assertRegex(fake, r"^\+\d{2} \d{5} \d{5}$")
        self.assertNotEqual(re.sub(r"\D", "", fake), "919876543210")

    def test_uses_obvious_generic_templates(self) -> None:
        self.assertEqual("John Doe", self.pseudonymizer.replace("PERSON", "Rashi Patil"))
        self.assertEqual("john.doe@example.com", self.pseudonymizer.replace("EMAIL_ADDRESS", "rashi@gmail.com"))
        self.assertEqual("www.example.com", self.pseudonymizer.replace("WEBSITE", "www.kshinternational. com"))
        self.assertEqual("Example Company Limited", self.pseudonymizer.replace("COMPANY", "ICICI Securities Limited"))

    def test_credit_card_replacement_passes_luhn(self) -> None:
        fake = self.pseudonymizer.replace("CREDIT_CARD", "4111 1111 1111 1111")
        digits = re.sub(r"\D", "", fake)
        total = 0
        parity = len(digits) % 2
        for index, char in enumerate(digits):
            value = int(char)
            if index % 2 == parity:
                value = value * 2 - 9 if value >= 5 else value * 2
            total += value
        self.assertEqual(0, total % 10)


if __name__ == "__main__":
    unittest.main()
