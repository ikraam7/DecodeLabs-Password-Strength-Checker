# Project Report

## 1. Project title

**Password Strength Checker**

## 2. Context

This project was completed as Project 1 of the DecodeLabs Cyber Security
Industrial Training Kit, Batch 2026.

The objective is to create a defensive security program that evaluates
password risk using string handling, conditional logic, data validation, and
basic entropy concepts.

## 3. Problem statement

Weak passwords expose accounts to brute-force and dictionary attacks. A
password-strength checker helps users identify missing security requirements
before a password is accepted or stored by another system.

## 4. Objectives

- Validate the minimum password length
- Detect uppercase and lowercase letters
- Detect numbers
- Detect special characters
- Classify the result as Weak, Medium, or Strong
- Give clear recommendations
- Avoid storing or displaying the entered password
- Keep the analysis efficient with O(n) complexity

## 5. Technologies

- Python 3
- `getpass` for hidden terminal input
- Unicode-aware string methods
- Generator expressions and `any()`
- `dataclasses` for structured output
- `unittest` for automated testing

## 6. IPO model

### Input

A password entered by the user through hidden terminal input.

### Process

The program checks:

1. Length
2. Lowercase letters
3. Uppercase letters
4. Digits
5. Special characters
6. Common passwords
7. Predictable sequences
8. Consecutive repeated characters

### Output

A security report containing:

- Weak, Medium, or Strong classification
- Policy score
- Estimated entropy
- PASS/FAIL checks
- Warnings
- Recommendations

## 7. Classification logic

A password shorter than 8 characters is immediately classified as Weak.

A password can be Medium when it has at least 8 characters and at least three
different character categories.

A password is Strong when it has at least 12 characters, contains all four
main categories, and does not contain a simple predictable pattern.

## 8. Unicode support

The project uses methods such as `islower()`, `isupper()`, `isdigit()`, and
`isalnum()`. These work with Unicode characters and are more flexible than
checks limited to ASCII ranges.

## 9. Computational efficiency

Character checks are implemented using generator expressions and `any()`.
Each check is a linear scan through the password. Because the number of scans
is fixed, the total complexity remains O(n).

## 10. Security considerations

The password:

- Is not written to disk
- Is not transmitted
- Is not included in the analysis result
- Is not printed after analysis

Python strings are immutable, so guaranteed memory wiping cannot be promised.
The project therefore limits the lifetime of the local password reference and
documents this limitation honestly.

Timing-safe comparison is important when comparing a supplied secret with a
stored secret. This checker does not perform such a comparison, so
`hmac.compare_digest()` is not required in its current workflow.

## 11. Testing

The test suite verifies:

- Immediate failure below 8 characters
- Common-password detection
- Medium classification
- Strong classification
- Unicode input
- Empty input
- Password non-disclosure
- Invalid input types

## 12. Conclusion

The project satisfies the required Password Strength Checker functionality
and adds practical security enhancements. It demonstrates secure input
handling, validation logic, Unicode support, clean Python code, and automated
testing.
