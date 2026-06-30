"""Automated tests for the DecodeLabs password-strength checker."""

import unittest

from password_checker import analyze_password


class PasswordCheckerTests(unittest.TestCase):
    def test_short_password_is_immediately_weak(self) -> None:
        # Contains all four categories but has only 7 characters.
        result = analyze_password("Aa1!xyz")
        self.assertEqual(result.strength, "Weak")
        self.assertFalse(result.checks["minimum_length_8"])

    def test_common_password_is_weak(self) -> None:
        result = analyze_password("password")
        self.assertEqual(result.strength, "Weak")
        self.assertFalse(result.checks["not_common_password"])

    def test_medium_password(self) -> None:
        result = analyze_password("Student9")
        self.assertEqual(result.strength, "Medium")
        self.assertFalse(result.checks["has_symbol"])

    def test_strong_password(self) -> None:
        result = analyze_password("Cyb3r!Defense#2026")
        self.assertEqual(result.strength, "Strong")
        self.assertTrue(result.checks["has_lowercase"])
        self.assertTrue(result.checks["has_uppercase"])
        self.assertTrue(result.checks["has_digit"])
        self.assertTrue(result.checks["has_symbol"])

    def test_unicode_password(self) -> None:
        result = analyze_password("Sécurité#2026A")
        self.assertTrue(result.checks["has_non_ascii"])
        self.assertTrue(result.checks["has_lowercase"])
        self.assertTrue(result.checks["has_uppercase"])
        self.assertTrue(result.checks["has_digit"])
        self.assertTrue(result.checks["has_symbol"])
        self.assertEqual(result.strength, "Strong")

    def test_empty_password(self) -> None:
        result = analyze_password("")
        self.assertEqual(result.strength, "Weak")
        self.assertEqual(result.estimated_entropy_bits, 0.0)

    def test_password_is_not_returned(self) -> None:
        password = "Private!Password2026"
        result = analyze_password(password)
        serialized = result.to_dict()
        self.assertNotIn("password", serialized)
        self.assertNotIn(password, str(serialized))

    def test_invalid_type(self) -> None:
        with self.assertRaises(TypeError):
            analyze_password(123456)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
