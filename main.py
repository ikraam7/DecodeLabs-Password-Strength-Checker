"""Command-line interface for DecodeLabs Cyber Security Project 1."""

from __future__ import annotations

from getpass import getpass

from password_checker import PasswordAnalysis, analyze_password


DISPLAY_CHECKS = {
    "minimum_length_8": "At least 8 characters",
    "recommended_length_12": "At least 12 characters",
    "has_lowercase": "Contains a lowercase letter",
    "has_uppercase": "Contains an uppercase letter",
    "has_digit": "Contains a number",
    "has_symbol": "Contains a special character",
    "not_common_password": "Not in the local common-password list",
    "no_predictable_sequence": "No predictable word or sequence",
    "no_triple_repetition": "No character repeated three times",
}


def _status(value: bool) -> str:
    return "PASS" if value else "FAIL"


def display_result(result: PasswordAnalysis) -> None:
    """Print a password-security report without displaying the password."""
    print("\n" + "=" * 62)
    print("PASSWORD STRENGTH REPORT")
    print("=" * 62)
    print(f"Strength                  : {result.strength}")
    print(f"Policy score              : {result.score}/{result.max_score}")
    print(
        "Estimated entropy        : "
        f"{result.estimated_entropy_bits:.2f} bits (educational estimate)"
    )

    print("\nSecurity checks")
    for key, label in DISPLAY_CHECKS.items():
        print(f"  [{_status(result.checks[key])}] {label}")

    if result.warnings:
        print("\nWarnings")
        for warning in result.warnings:
            print(f"  - {warning}")

    print("\nRecommendations")
    for recommendation in result.recommendations:
        print(f"  - {recommendation}")

    print("=" * 62)


def main() -> None:
    print("=" * 62)
    print("DecodeLabs - Cyber Security Project 1")
    print("Password Strength Checker")
    print("=" * 62)
    print("The password is checked locally and is not stored.")
    print("Type q to close the program.")
    print(
        "Note: nothing appears while you type because secure hidden input is used.\n"
    )

    while True:
        try:
            password = getpass("Enter a password to analyze: ")
        except (EOFError, KeyboardInterrupt):
            print("\nProgram closed safely.")
            break

        if password.casefold() == "q":
            print("Goodbye.")
            break

        result = analyze_password(password)
        display_result(result)

        # Best-effort removal of the local reference. Python strings are
        # immutable, so guaranteed memory wiping is outside this project's scope.
        password = ""
        print()


if __name__ == "__main__":
    main()
