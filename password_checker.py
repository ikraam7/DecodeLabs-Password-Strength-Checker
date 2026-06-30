"""Password-strength analysis for DecodeLabs Cyber Security Project 1.

The implementation uses Python string methods so that character checks work
with both ASCII and Unicode input. Passwords are analyzed locally and are
never written to disk or included in the returned result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any


# A small local list for the optional "common/leaked password" enhancement
# suggested in the project brief. It is intentionally kept offline.
COMMON_PASSWORDS = {
    "123456",
    "12345678",
    "123456789",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
}

PREDICTABLE_SEQUENCES = (
    "1234",
    "abcd",
    "qwerty",
    "azerty",
    "password",
    "admin",
)


@dataclass(frozen=True)
class PasswordAnalysis:
    """Structured password-analysis result."""

    strength: str
    score: int
    max_score: int
    estimated_entropy_bits: float
    checks: dict[str, bool]
    warnings: list[str]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable result that never contains the password."""
        return asdict(self)


def _estimate_entropy(password: str, checks: dict[str, bool]) -> float:
    """Return a rough search-space entropy estimate.

    This value is educational rather than cryptographically exact. Unicode
    input receives an expanded pool estimate because Python's string methods
    support characters beyond ASCII.
    """
    if not password:
        return 0.0

    pool_size = 0

    if checks["has_lowercase"]:
        pool_size += 26
    if checks["has_uppercase"]:
        pool_size += 26
    if checks["has_digit"]:
        pool_size += 10
    if checks["has_symbol"]:
        pool_size += 33
    if checks["has_non_ascii"]:
        pool_size += 100

    if pool_size == 0:
        return 0.0

    return round(len(password) * math.log2(pool_size), 2)


def analyze_password(password: str) -> PasswordAnalysis:
    """Analyze a password and classify it as Weak, Medium, or Strong.

    Core policy:
    - Fewer than 8 characters: immediate Weak classification.
    - Medium: at least 8 characters and at least three character categories.
    - Strong: at least 12 characters, all four categories, and no obvious
      common/predictable pattern.

    The character-category checks use ``any()`` with Python's Unicode-aware
    string methods. Each scan is linear, so total time complexity remains O(n).
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)

    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(
        not char.isalnum() and not char.isspace()
        for char in password
    )
    contains_whitespace = any(char.isspace() for char in password)
    has_non_ascii = any(ord(char) > 127 for char in password)

    checks = {
        "minimum_length_8": length >= 8,
        "recommended_length_12": length >= 12,
        "has_lowercase": has_lowercase,
        "has_uppercase": has_uppercase,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "contains_whitespace": contains_whitespace,
        "has_non_ascii": has_non_ascii,
    }

    normalized = password.casefold()
    is_common = normalized in COMMON_PASSWORDS
    has_predictable_sequence = any(
        sequence in normalized for sequence in PREDICTABLE_SEQUENCES
    )
    has_repeated_characters = any(
        password[index] == password[index + 1] == password[index + 2]
        for index in range(max(0, length - 2))
    )

    checks["not_common_password"] = not is_common
    checks["no_predictable_sequence"] = not has_predictable_sequence
    checks["no_triple_repetition"] = not has_repeated_characters

    category_count = sum(
        (
            has_lowercase,
            has_uppercase,
            has_digit,
            has_symbol,
        )
    )

    # Simple score for visual feedback. Maximum: 7.
    score = sum(
        (
            length >= 8,
            length >= 12,
            has_lowercase,
            has_uppercase,
            has_digit,
            has_symbol,
            not is_common,
        )
    )

    warnings: list[str] = []
    recommendations: list[str] = []

    if length < 8:
        warnings.append(
            "Immediate failure: the password contains fewer than 8 characters."
        )
        recommendations.append("Use at least 8 characters.")
    elif length < 12:
        recommendations.append(
            "Use 12 or more characters to reach the recommended length."
        )

    if not has_lowercase:
        recommendations.append("Add at least one lowercase letter.")
    if not has_uppercase:
        recommendations.append("Add at least one uppercase letter.")
    if not has_digit:
        recommendations.append("Add at least one number.")
    if not has_symbol:
        recommendations.append("Add at least one special character.")

    if is_common:
        warnings.append("This password appears in the local common-password list.")
    if has_predictable_sequence:
        warnings.append("The password contains a predictable word or sequence.")
    if has_repeated_characters:
        warnings.append(
            "Avoid repeating the same character three or more times consecutively."
        )
    if contains_whitespace:
        warnings.append(
            "Whitespace is allowed, but it is not counted as a special character."
        )

    # Mandatory rule from the project brief: less than 8 = immediate Weak.
    if length < 8 or is_common:
        strength = "Weak"
    elif (
        length >= 12
        and category_count == 4
        and not has_predictable_sequence
        and not has_repeated_characters
    ):
        strength = "Strong"
    elif category_count >= 3:
        strength = "Medium"
    else:
        strength = "Weak"

    if not warnings and not recommendations:
        recommendations.append(
            "The password meets the recommended length and variety requirements."
        )

    return PasswordAnalysis(
        strength=strength,
        score=score,
        max_score=7,
        estimated_entropy_bits=_estimate_entropy(password, checks),
        checks=checks,
        warnings=warnings,
        recommendations=recommendations,
    )
