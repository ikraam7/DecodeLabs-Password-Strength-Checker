# Security Notes

## 1. Passwords in memory

Python strings are immutable. Once a password has been entered, the program
cannot guarantee that every copy is overwritten immediately in RAM.

This project reduces exposure by:

- Avoiding logs
- Avoiding files
- Avoiding network transmission
- Avoiding printing the original password
- Keeping the password reference local
- Replacing the local reference after analysis

This is best-effort handling, not guaranteed secure memory erasure.

## 2. Timing attacks

Timing attacks matter when a program compares an attacker-controlled value
with a secret value and exits at different positions.

For authentication code, use:

```python
import hmac

is_equal = hmac.compare_digest(provided_value, expected_value)
```

The Password Strength Checker does not compare an entered password against a
stored secret. Therefore, constant-time comparison is not part of its main
logic.

## 3. Validation before hashing

This project validates password strength only.

A future registration system should follow this order:

1. Validate password policy
2. Reject weak input
3. Generate a unique salt
4. Hash the accepted password with a password-hashing algorithm
5. Store only the resulting hash and required parameters

Plaintext passwords must never be stored.

## 4. Entropy estimate

The displayed entropy is an educational approximation. It is not a guarantee
of resistance against real-world cracking because attackers also exploit
human patterns, reused passwords, leaked credentials, and dictionaries.
