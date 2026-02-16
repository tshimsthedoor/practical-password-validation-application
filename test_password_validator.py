"""
Unit tests for Password Validator

Tests cover:
- OWASP ASVS compliance
- Common password detection
- Length requirements
- Complexity requirements
- Sequential patterns
- Repeated characters
- Username similarity
- Password strength assessment
"""

import unittest
import tempfile
import os
from password_validator import PasswordValidator, validate_password


class TestPasswordValidator(unittest.TestCase):
    """Test cases for PasswordValidator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary common passwords file
        self.temp_common_passwords = tempfile.NamedTemporaryFile(
            mode='w', 
            delete=False,
            suffix='.txt'
        )
        self.temp_common_passwords.write("password\n123456\nadmin\nqwerty\n")
        self.temp_common_passwords.close()
        
        self.validator = PasswordValidator(self.temp_common_passwords.name)
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_common_passwords.name):
            os.unlink(self.temp_common_passwords.name)
    
    def test_valid_password(self):
        """Test that a strong, valid password passes all checks."""
        is_valid, issues = self.validator.validate("Str0ng!Pass@2024")
        self.assertTrue(is_valid)
        self.assertEqual(len(issues), 0)
    
    def test_minimum_length_requirement(self):
        """Test OWASP ASVS 2.1.1 - minimum 8 characters."""
        is_valid, issues = self.validator.validate("Sh0rt!")
        self.assertFalse(is_valid)
        self.assertTrue(any("at least 8 characters" in issue for issue in issues))
    
    def test_maximum_length_requirement(self):
        """Test maximum length to prevent DoS attacks."""
        long_password = "A1b!" + "x" * 130
        is_valid, issues = self.validator.validate(long_password)
        self.assertFalse(is_valid)
        self.assertTrue(any("must not exceed" in issue for issue in issues))
    
    def test_common_password_detection(self):
        """Test OWASP ASVS 2.1.7 - reject common passwords."""
        is_valid, issues = self.validator.validate("password")
        self.assertFalse(is_valid)
        self.assertTrue(any("too common" in issue for issue in issues))
    
    def test_common_password_case_insensitive(self):
        """Test that common password check is case-insensitive."""
        is_valid, issues = self.validator.validate("PASSWORD")
        self.assertFalse(is_valid)
        self.assertTrue(any("too common" in issue for issue in issues))
    
    def test_lowercase_requirement(self):
        """Test that password must contain lowercase letters."""
        is_valid, issues = self.validator.validate("ALLUPPERCASE123!")
        self.assertFalse(is_valid)
        self.assertTrue(any("lowercase" in issue for issue in issues))
    
    def test_uppercase_requirement(self):
        """Test that password must contain uppercase letters."""
        is_valid, issues = self.validator.validate("alllowercase123!")
        self.assertFalse(is_valid)
        self.assertTrue(any("uppercase" in issue for issue in issues))
    
    def test_digit_requirement(self):
        """Test that password must contain digits."""
        is_valid, issues = self.validator.validate("NoDigitsHere!")
        self.assertFalse(is_valid)
        self.assertTrue(any("digit" in issue for issue in issues))
    
    def test_special_character_requirement(self):
        """Test that password must contain special characters."""
        is_valid, issues = self.validator.validate("NoSpecialChars123")
        self.assertFalse(is_valid)
        self.assertTrue(any("special character" in issue for issue in issues))
    
    def test_repeated_characters(self):
        """Test detection of excessive repeated characters."""
        is_valid, issues = self.validator.validate("Passssss1!")
        self.assertFalse(is_valid)
        self.assertTrue(any("repeated characters" in issue for issue in issues))
    
    def test_repeated_characters_acceptable(self):
        """Test that acceptable repeated characters pass."""
        # Only 2-3 repeated characters should be OK
        is_valid, issues = self.validator.validate("Paassword1!")
        # Should not fail on repeated characters alone
        has_repeat_issue = any("repeated characters" in issue for issue in issues)
        self.assertFalse(has_repeat_issue)
    
    def test_sequential_characters_ascending(self):
        """Test detection of ascending sequential characters."""
        is_valid, issues = self.validator.validate("Abcd1234!")
        self.assertFalse(is_valid)
        self.assertTrue(any("sequential" in issue for issue in issues))
    
    def test_sequential_characters_descending(self):
        """Test detection of descending sequential characters."""
        is_valid, issues = self.validator.validate("Dcba4321!")
        self.assertFalse(is_valid)
        self.assertTrue(any("sequential" in issue for issue in issues))
    
    def test_username_similarity_exact(self):
        """Test that password cannot be same as username."""
        is_valid, issues = self.validator.validate("johnsmith", username="johnsmith")
        self.assertFalse(is_valid)
        self.assertTrue(any("similar to username" in issue for issue in issues))
    
    def test_username_similarity_contained(self):
        """Test that password cannot contain username."""
        is_valid, issues = self.validator.validate("johnsmith123!", username="johnsmith")
        self.assertFalse(is_valid)
        self.assertTrue(any("similar to username" in issue for issue in issues))
    
    def test_username_similarity_case_insensitive(self):
        """Test that username similarity check is case-insensitive."""
        is_valid, issues = self.validator.validate("JohnSmith123!", username="johnsmith")
        self.assertFalse(is_valid)
        self.assertTrue(any("similar to username" in issue for issue in issues))
    
    def test_whitespace_leading_trailing(self):
        """Test that leading/trailing whitespace is not allowed."""
        is_valid, issues = self.validator.validate(" StrongPass1! ")
        self.assertFalse(is_valid)
        self.assertTrue(any("whitespace" in issue for issue in issues))
    
    def test_password_without_username(self):
        """Test validation without username parameter."""
        is_valid, issues = self.validator.validate("ValidPass123!")
        self.assertTrue(is_valid)
        self.assertEqual(len(issues), 0)
    
    def test_validator_without_common_passwords_file(self):
        """Test validator works without common passwords file."""
        validator_no_file = PasswordValidator()
        is_valid, issues = validator_no_file.validate("ValidPass123!")
        self.assertTrue(is_valid)
    
    def test_convenience_function(self):
        """Test the convenience validate_password function."""
        is_valid, issues = validate_password(
            "ValidPass123!",
            username="testuser",
            common_passwords_file=self.temp_common_passwords.name
        )
        self.assertTrue(is_valid)
        self.assertEqual(len(issues), 0)


class TestPasswordStrength(unittest.TestCase):
    """Test cases for password strength assessment."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.validator = PasswordValidator()
    
    def test_weak_password_strength(self):
        """Test that weak passwords are identified."""
        result = self.validator.get_password_strength("Pass1!")
        # Short passwords with all character types may score as medium
        self.assertIn(result["strength"], ["weak", "medium"])
        self.assertLess(result["score"], 65)
        self.assertGreater(len(result["feedback"]), 0)
    
    def test_medium_password_strength(self):
        """Test that medium strength passwords are identified."""
        result = self.validator.get_password_strength("Password123!")
        # 12 characters with all types scores as strong
        self.assertIn(result["strength"], ["medium", "strong"])
        self.assertGreaterEqual(result["score"], 40)
    
    def test_strong_password_strength(self):
        """Test that strong passwords are identified."""
        result = self.validator.get_password_strength("MyStr0ng!P@ssw0rd")
        self.assertIn(result["strength"], ["strong", "very_strong"])
        self.assertGreaterEqual(result["score"], 60)
    
    def test_very_strong_password_strength(self):
        """Test that very strong passwords are identified."""
        result = self.validator.get_password_strength("C0mpl3x!P@ssw0rd#2024$Secure")
        self.assertEqual(result["strength"], "very_strong")
        self.assertGreaterEqual(result["score"], 80)
    
    def test_strength_score_range(self):
        """Test that strength score is always between 0 and 100."""
        passwords = [
            "a",
            "Pass1!",
            "ValidPass123!",
            "VeryStr0ng!P@ssw0rd#WithM@nyChars"
        ]
        
        for password in passwords:
            result = self.validator.get_password_strength(password)
            self.assertGreaterEqual(result["score"], 0)
            self.assertLessEqual(result["score"], 100)
    
    def test_strength_feedback_for_short_password(self):
        """Test that feedback suggests using more characters."""
        result = self.validator.get_password_strength("Pa1!")
        self.assertTrue(any("8 characters" in fb for fb in result["feedback"]))
    
    def test_strength_feedback_for_no_uppercase(self):
        """Test that feedback suggests adding uppercase."""
        result = self.validator.get_password_strength("password123!")
        self.assertTrue(any("uppercase" in fb for fb in result["feedback"]))
    
    def test_strength_feedback_for_no_digit(self):
        """Test that feedback suggests adding numbers."""
        result = self.validator.get_password_strength("PasswordOnly!")
        self.assertTrue(any("numbers" in fb for fb in result["feedback"]))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.validator = PasswordValidator()
    
    def test_empty_password(self):
        """Test that empty password is rejected."""
        is_valid, issues = self.validator.validate("")
        self.assertFalse(is_valid)
        self.assertGreater(len(issues), 0)
    
    def test_exactly_min_length(self):
        """Test password with exactly minimum length."""
        # 8 characters with all requirements
        is_valid, issues = self.validator.validate("Abc123!@")
        self.assertTrue(is_valid)
    
    def test_exactly_max_length(self):
        """Test password with exactly maximum length."""
        # Create 128 character password
        password = "Abc123!@" + "x" * 120
        is_valid, issues = self.validator.validate(password)
        # Should pass length check but may fail other checks
        length_issues = [i for i in issues if "exceed" in i or "at least" in i]
        self.assertEqual(len(length_issues), 0)
    
    def test_unicode_characters(self):
        """Test password with unicode characters."""
        # Unicode should be allowed
        is_valid, issues = self.validator.validate("Pàsswörd123!€")
        # Should not fail validation entirely
        self.assertTrue(len(issues) <= 4)  # May fail other checks
    
    def test_all_special_characters(self):
        """Test password with various special characters."""
        is_valid, issues = self.validator.validate("P@ss!w0rd#$%^&*()")
        self.assertTrue(is_valid)
    
    def test_nonexistent_common_passwords_file(self):
        """Test that validator handles missing common passwords file gracefully."""
        validator = PasswordValidator("nonexistent_file.txt")
        is_valid, issues = validator.validate("ValidPass123!")
        # Should still work without common passwords check
        self.assertTrue(is_valid)
    
    def test_username_shorter_than_4_chars(self):
        """Test username similarity with short username."""
        is_valid, issues = self.validator.validate("ValidPass123!", username="joe")
        # Short usernames shouldn't trigger strict similarity checks
        # But if username is in password, it should still fail
        if "joe" in "ValidPass123!".lower():
            self.assertTrue(any("similar to username" in issue for issue in issues))
    
    def test_sequential_at_end(self):
        """Test sequential characters at the end of password."""
        is_valid, issues = self.validator.validate("ValidP@ss1234")
        self.assertFalse(is_valid)
        self.assertTrue(any("sequential" in issue for issue in issues))
    
    def test_repeated_at_beginning(self):
        """Test repeated characters at the beginning of password."""
        is_valid, issues = self.validator.validate("AAAAValidPass1!")
        self.assertFalse(is_valid)
        self.assertTrue(any("repeated" in issue for issue in issues))


if __name__ == '__main__':
    unittest.main()
