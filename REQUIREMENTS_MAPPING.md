# Official Requirements Mapping

| PDF requirement | Implementation |
|---|---|
| Create a password-strength checker | `main.py` and `password_checker.py` |
| Weak, Medium, Strong result | `analyze_password()` classification |
| Check password length | `minimum_length_8` and `recommended_length_12` |
| Less than 8 = immediate failure | Explicit first classification rule |
| Check uppercase letters | `any(char.isupper() ...)` |
| Check lowercase letters | `any(char.islower() ...)` |
| Check numbers | `any(char.isdigit() ...)` |
| Check symbols | Unicode-aware `not char.isalnum()` check |
| Display the result | `display_result()` |
| String handling and conditional checks | Core analysis logic |
| O(n) processing | Fixed number of linear scans |
| Pythonic `any()` approach | Used for all character checks |
| Unicode awareness | Python Unicode string methods |
| Do not retain sensitive input | No logging, saving, or network transfer |
| Common/leaked-password enhancement | Small offline `COMMON_PASSWORDS` set |
| Validation before later hashing/encryption | Documented architecture boundary |

## Notes on advanced slides

The PDF discusses RAM scraping, immutable Python strings, timing attacks, and
constant-time comparison.

These topics are documented in `SECURITY_NOTES.md`. They are not artificially
added to the main code because this project only evaluates password strength;
it does not authenticate users or compare an entered secret with a stored
secret.
