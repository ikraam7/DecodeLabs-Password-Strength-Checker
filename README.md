# DecodeLabs Cyber Security Internship - Project 1

## Password Strength Checker

This Python project analyzes a password and classifies it as:

- **Weak**
- **Medium**
- **Strong**

It was developed for **DecodeLabs Cyber Security Project 1, Batch 2026**.

## Official requirements implemented

The application:

- Checks password length
- Immediately classifies passwords shorter than 8 characters as Weak
- Checks uppercase letters
- Checks lowercase letters
- Checks numbers
- Checks special characters
- Displays the final password-strength result
- Uses Python string handling and conditional logic
- Uses Unicode-aware Python string methods
- Has O(n) time complexity
- Does not save or transmit passwords

## Additional improvements

The project also includes:

- A local common-password check
- Predictable-sequence detection
- Repeated-character detection
- A rough educational entropy estimate
- Hidden terminal input with `getpass`
- Automated unit tests
- Detailed recommendations
- Unicode password support

## Project structure

```text
DecodeLabs_Project1_Password_Strength_Checker_Final/
├── main.py
├── password_checker.py
├── README.md
├── PROJECT_REPORT.md
├── REQUIREMENTS_MAPPING.md
├── SECURITY_NOTES.md
├── SUBMISSION_CHECKLIST.md
├── TEST_RESULTS.txt
├── requirements.txt
├── screenshots/
│   └── README.md
|   └── 01_project_structure
|   └── 02_program_start
|   └── 03_weak_password
|   └── 04_medium_password
|   └── 05_strong_password
|   └── 06_unicode_password
|   └── 07_tests_passed
|   └── 08_password_checks_code
|   └── 09_classification_logic
└── tests/
    └── test_password_checker.py
```

## Requirements

- Python 3.10 or later
- No external package is required

## Run the program

Open a terminal inside the project directory:

```bash
python main.py
```

On Windows:

```powershell
py main.py
```

Nothing appears while the password is being typed. This is normal because
the application uses secure hidden input.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Classification policy

### Weak

A password is classified as Weak when:

- It has fewer than 8 characters, or
- It is found in the local common-password list, or
- It does not contain enough character variety

### Medium

A password is classified as Medium when:

- It has at least 8 characters, and
- It contains at least three character categories

### Strong

A password is classified as Strong when:

- It has at least 12 characters
- It contains lowercase and uppercase letters
- It contains at least one number
- It contains at least one special character
- It does not contain an obvious predictable sequence
- It does not contain a character repeated three times consecutively

## Safe examples for screenshots

Do not test with a real personal password.

```text
Weak:   Aa1!xyz
Medium: Student9
Strong: Cyb3r!Defense#2026
Unicode example: Sécurité#2026A
```

## Complexity

The program uses generator expressions with `any()` and Python string
methods such as:

```python
has_digit = any(char.isdigit() for char in password)
```

Each check performs a linear scan. A fixed number of linear scans still gives
an overall time complexity of **O(n)**.

## Privacy

- The password is never written to a file
- The password is never sent over the network
- The password is never printed in the report
- The returned analysis object contains only derived results
- Python does not guarantee secure in-place erasure of immutable strings

## Author

**Name:** Ikram LAABOUKI 
**Internship:** DecodeLabs Cyber Security Internship  
**Project:** Project 1 - Password Strength Checker  
**Batch:** 2026
