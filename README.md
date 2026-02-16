# Practical Password Validation Application

[![Security](https://img.shields.io/badge/Security-OWASP%20Compliant-green.svg)](https://owasp.org/)
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)

A comprehensive, production-ready password validation library following **OWASP (Open Web Application Security Project)** guidelines and best practices for secure authentication.

## 🔒 Security Features

This password validator implements multiple layers of security checks based on:

- **OWASP ASVS** (Application Security Verification Standard)
- **OWASP Authentication Cheat Sheet**
- **NIST Digital Identity Guidelines**
- **Common credential attack pattern prevention**

### Key Security Validations

✅ **Length Requirements**
- Minimum 8 characters (OWASP ASVS 2.1.1)
- Maximum 128 characters (DoS prevention)

✅ **Common Password Detection** (OWASP ASVS 2.1.7)
- Checks against database of commonly used passwords
- Prevents dictionary attacks

✅ **Complexity Requirements**
- Uppercase letters (A-Z)
- Lowercase letters (a-z)
- Digits (0-9)
- Special characters (!@#$%^&*, etc.)

✅ **Pattern Detection**
- Sequential characters (abc, 123, xyz)
- Repeated characters (aaaa, 1111)
- Prevents predictable passwords

✅ **Contextual Validation**
- Username similarity checking
- Prevents user-related password patterns

✅ **Additional Checks**
- No leading/trailing whitespace
- Unicode support
- Password strength scoring

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/tshimsthedoor/practical-password-validation-application.git
cd practical-password-validation-application

# Install optional frontend/backend dependencies
pip install -r requirements.txt
```

### Basic Usage

```python
from password_validator import PasswordValidator

# Initialize validator with common passwords list
validator = PasswordValidator("common_passwords.txt")

# Validate a password
is_valid, issues = validator.validate("MySecure!P@ss2024", username="john")

if is_valid:
    print("✓ Password is secure!")
else:
    print("✗ Password validation failed:")
    for issue in issues:
        print(f"  - {issue}")

# Get password strength assessment
strength = validator.get_password_strength("MySecure!P@ss2024")
print(f"Strength: {strength['strength']} (Score: {strength['score']}/100)")
```

### Convenience Function

```python
from password_validator import validate_password

is_valid, issues = validate_password(
    password="MySecure!P@ss2024",
    username="john",
    common_passwords_file="common_passwords.txt"
)
```

## 📖 Detailed Usage

### Password Validation

The `validate()` method returns a tuple of `(bool, List[str])`:

```python
validator = PasswordValidator("common_passwords.txt")

# Example 1: Valid password
is_valid, issues = validator.validate("Str0ng!P@ssw0rd")
# Returns: (True, [])

# Example 2: Invalid password
is_valid, issues = validator.validate("weak")
# Returns: (False, ['Password must be at least 8 characters long', ...])

# Example 3: Check with username
is_valid, issues = validator.validate("johnsmith123", username="johnsmith")
# Returns: (False, ['Password is too similar to username', ...])
```

### Password Strength Assessment

Get detailed password strength metrics:

```python
validator = PasswordValidator()
result = validator.get_password_strength("MyP@ssw0rd123")

print(result)
# {
#   'strength': 'strong',           # weak, medium, strong, or very_strong
#   'score': 75,                     # 0-100
#   'feedback': ['Add more length']  # Improvement suggestions
# }
```

## 🧪 Running Tests

Comprehensive test suite with 30+ test cases:

```bash
# Run all tests
python -m unittest test_password_validator.py

# Run with verbose output
python -m unittest test_password_validator.py -v

# Run specific test class
python -m unittest test_password_validator.TestPasswordValidator

# Run specific test
python -m unittest test_password_validator.TestPasswordValidator.test_valid_password
```

## 🎯 Demo

Run the interactive demo to see examples:

```bash
python demo.py
```

The demo showcases:
- Strong valid passwords
- Common validation failures
- Strength assessment
- Username similarity detection
- Pattern detection (sequential, repeated)

## 🖥️ Web Frontend (Streamlit)

A modern web UI is included in `app.py` so you can validate passwords visually.
The frontend calls the FastAPI backend endpoints (`/validate` and `/strength`).

### Run the frontend

```bash
# Install dependencies
pip install -r requirements.txt

# Start API first (required)
uvicorn api:app --reload

# Launch web app in a second terminal
streamlit run app.py
```

Then open the local URL shown in the terminal (usually `http://localhost:8501`).
In the sidebar, keep `Backend URL` as `http://127.0.0.1:8000` unless your API runs elsewhere.

## ⚡ Backend API (FastAPI)

A REST API is included in `api.py` for integration with web/mobile apps or other services.

### Run the API

```bash
# Install dependencies
pip install -r requirements.txt

# Launch API server
uvicorn api:app --reload
```

Open API docs at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

### API Endpoints

- `GET /health` → service health check
- `POST /validate` → validates password policy rules
- `POST /strength` → returns strength score and feedback

### Example Requests

```bash
curl -X POST "http://127.0.0.1:8000/validate" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"MySecure!P@ss2026\",\"username\":\"john\"}"

curl -X POST "http://127.0.0.1:8000/strength" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"MySecure!P@ss2026\"}"
```

## ▶️ Run Both Frontend + API

Use two terminals from the project root:

```bash
# Terminal 1: API
uvicorn api:app --reload

# Terminal 2: Frontend
streamlit run app.py
```

Then open:
- Frontend: `http://localhost:8501`
- API Docs: `http://127.0.0.1:8000/docs`

## 📋 OWASP Compliance Checklist

This implementation follows these OWASP guidelines:

- ✅ **ASVS 2.1.1**: Minimum 8 character passwords
- ✅ **ASVS 2.1.2**: Maximum length limit (128 chars)
- ✅ **ASVS 2.1.7**: Common password checking
- ✅ **ASVS 2.1.8**: No password composition rules that reduce entropy
- ✅ **Authentication Cheat Sheet**: Multi-factor character type requirements
- ✅ **Authentication Cheat Sheet**: Context-aware validation (username check)

## 🛡️ Security Best Practices

### What This Validator Does

1. **Prevents Common Attacks**
   - Dictionary attacks (common password list)
   - Brute force attacks (complexity requirements)
   - Pattern-based attacks (sequential/repeated detection)
   - Social engineering (username similarity)

2. **Follows Modern Standards**
   - Prioritizes length over complexity
   - No artificial composition rules
   - User-friendly error messages
   - Strength-based guidance

### What This Validator Does NOT Do

This is a **client-side validation** library. For complete security:

1. **Always validate on the server-side** - Client-side validation can be bypassed
2. **Use secure password storage** - Hash with bcrypt, Argon2, or PBKDF2
3. **Implement rate limiting** - Prevent brute force attempts
4. **Use HTTPS** - Encrypt passwords in transit
5. **Consider MFA** - Multi-factor authentication adds security
6. **Monitor for breaches** - Check against Have I Been Pwned API

## 🔧 Configuration

### Custom Common Passwords List

Create your own common passwords file:

```python
# Format: one password per line
validator = PasswordValidator("my_passwords.txt")
```

### Adjust Security Parameters

Modify class constants for your needs:

```python
class PasswordValidator:
    MIN_LENGTH = 8              # Minimum length
    MAX_LENGTH = 128            # Maximum length  
    MAX_REPEATED_CHARS = 3      # Max repeated chars
    MAX_SEQUENTIAL_CHARS = 3    # Max sequential chars
```

## 📊 Test Coverage

Comprehensive test suite with 37 test cases:

- ✅ Valid password acceptance
- ✅ Length requirement enforcement
- ✅ Common password detection
- ✅ Complexity requirement validation
- ✅ Pattern detection (sequential, repeated)
- ✅ Username similarity checking
- ✅ Whitespace handling
- ✅ Edge cases and boundary conditions
- ✅ Password strength assessment
- ✅ Unicode character support

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. New features include tests
3. Code follows OWASP guidelines
4. Documentation is updated

## 📄 License

This project is open source and available for educational and commercial use.

## 🔗 References

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## 👨‍💻 Author

Created as a practical implementation of OWASP password security guidelines.

---

**Remember**: Password validation is just one part of a complete security strategy. Always implement defense in depth!
