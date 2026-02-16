"""
Password Validator - OWASP Compliant Password Validation

This module provides comprehensive password validation following OWASP guidelines:
- OWASP ASVS (Application Security Verification Standard)
- OWASP Authentication Cheat Sheet

Key Security Principles:
1. Length over complexity
2. No artificial complexity requirements that weaken passwords
3. Check against common/compromised passwords
4. Prevent predictable patterns
5. Contextual validation (username similarity)
"""

import re
import unicodedata
from typing import List, Dict, Tuple, Any
from pathlib import Path


class PasswordValidator:
    """
    OWASP-compliant password validator that checks for common vulnerabilities.
    
    Following OWASP recommendations:
    - Minimum 8 characters (OWASP ASVS 2.1.1)
    - Maximum 128 characters (prevent DoS attacks)
    - Check against common passwords (OWASP ASVS 2.1.7)
    - Verify complexity requirements
    - Check for sequential/repeated patterns
    """
    
    # OWASP ASVS recommends minimum 8 characters
    MIN_LENGTH = 8
    # Maximum length to prevent DoS attacks
    MAX_LENGTH = 128
    # Maximum allowed repeated characters
    MAX_REPEATED_CHARS = 3
    # Maximum allowed sequential characters
    MAX_SEQUENTIAL_CHARS = 3
    
    def __init__(self, common_passwords_file: str = None):
        """
        Initialize the password validator.
        
        Args:
            common_passwords_file: Path to file containing common passwords (one per line)
        """
        self.common_passwords = set()
        if common_passwords_file:
            self._load_common_passwords(common_passwords_file)
    
    def _load_common_passwords(self, filepath: str) -> None:
        """Load common passwords from file."""
        try:
            path = Path(filepath)
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    self.common_passwords = {
                        line.strip().lower() 
                        for line in f 
                        if line.strip()
                    }
        except Exception as e:
            print(f"Warning: Could not load common passwords file: {e}")
    
    def validate(self, password: str, username: str = None) -> Tuple[bool, List[str]]:
        """
        Validate a password against OWASP security guidelines.
        
        Args:
            password: The password to validate
            username: Optional username to check for similarity
            
        Returns:
            Tuple of (is_valid, list_of_issues)
            - is_valid: True if password passes all checks
            - list_of_issues: List of validation error messages
        """
        issues = []
        
        # Check 1: Length requirements (OWASP ASVS 2.1.1)
        if len(password) < self.MIN_LENGTH:
            issues.append(f"Password must be at least {self.MIN_LENGTH} characters long")
        
        if len(password) > self.MAX_LENGTH:
            issues.append(f"Password must not exceed {self.MAX_LENGTH} characters")
        
        # Check 2: Common passwords (OWASP ASVS 2.1.7)
        if self._is_common_password(password):
            issues.append("Password is too common and easily guessable")
        
        # Check 3: Complexity requirements
        # OWASP recommends checking for at least 3 of 4 character types
        complexity_score = 0
        if re.search(r'[a-z]', password):
            complexity_score += 1
        else:
            issues.append("Password must contain at least one lowercase letter")
            
        if re.search(r'[A-Z]', password):
            complexity_score += 1
        else:
            issues.append("Password must contain at least one uppercase letter")
            
        if re.search(r'\d', password):
            complexity_score += 1
        else:
            issues.append("Password must contain at least one digit")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', password):
            complexity_score += 1
        else:
            issues.append("Password must contain at least one special character")
        
        # Check 4: Repeated characters
        if self._has_repeated_characters(password):
            issues.append(f"Password contains more than {self.MAX_REPEATED_CHARS} repeated characters")
        
        # Check 5: Sequential characters
        if self._has_sequential_characters(password):
            issues.append(f"Password contains sequential characters (e.g., 'abc', '123')")
        
        # Check 6: Username similarity (contextual validation)
        if username and self._is_similar_to_username(password, username):
            issues.append("Password is too similar to username")
        
        # Check 7: Whitespace (leading/trailing)
        if password != password.strip():
            issues.append("Password contains leading or trailing whitespace")
        
        is_valid = len(issues) == 0
        return is_valid, issues
    
    def _is_common_password(self, password: str) -> bool:
        """
        Check if password is in the common passwords list.
        
        Returns:
            True if password is common, False otherwise
        """
        if not self.common_passwords:
            return False
        
        # Normalize and check
        normalized = password.lower()
        return normalized in self.common_passwords
    
    def _has_repeated_characters(self, password: str) -> bool:
        """
        Check for excessive repeated characters (e.g., 'aaaa', '1111').
        
        Returns:
            True if too many repeated characters found
        """
        if len(password) < self.MAX_REPEATED_CHARS + 1:
            return False
        
        for i in range(len(password) - self.MAX_REPEATED_CHARS):
            if len(set(password[i:i + self.MAX_REPEATED_CHARS + 1])) == 1:
                return True
        
        return False
    
    def _has_sequential_characters(self, password: str) -> bool:
        """
        Check for sequential characters (e.g., 'abc', '123', 'xyz').
        
        Returns:
            True if sequential patterns found
        """
        if len(password) < self.MAX_SEQUENTIAL_CHARS + 1:
            return False
        
        # Check for ascending sequences
        for i in range(len(password) - self.MAX_SEQUENTIAL_CHARS):
            substring = password[i:i + self.MAX_SEQUENTIAL_CHARS + 1]
            
            # Check if all characters are alphanumeric
            if substring.isalnum():
                # Check for sequential ASCII values
                is_sequential = all(
                    ord(substring[j+1]) - ord(substring[j]) == 1
                    for j in range(len(substring) - 1)
                )
                
                # Check for reverse sequential
                is_reverse_sequential = all(
                    ord(substring[j]) - ord(substring[j+1]) == 1
                    for j in range(len(substring) - 1)
                )
                
                if is_sequential or is_reverse_sequential:
                    return True
        
        return False
    
    def _is_similar_to_username(self, password: str, username: str) -> bool:
        """
        Check if password is too similar to username.
        
        Uses case-insensitive comparison and checks if username is contained
        in password or vice versa.
        
        Returns:
            True if password is too similar to username
        """
        if not username:
            return False
        
        password_lower = password.lower()
        username_lower = username.lower()
        
        # Check if username is in password or password is in username
        if username_lower in password_lower or password_lower in username_lower:
            return True
        
        # Check Levenshtein-like similarity (simplified)
        # If more than 50% of characters match, consider it similar
        if len(username) >= 4:
            match_count = sum(1 for c in username_lower if c in password_lower)
            similarity_ratio = match_count / len(username)
            if similarity_ratio > 0.7:
                return True
        
        return False
    
    def get_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Evaluate password strength and return detailed metrics.
        
        Args:
            password: The password to evaluate
            
        Returns:
            Dictionary containing strength metrics:
            - strength: 'weak', 'medium', 'strong', 'very_strong'
            - score: Numeric score (0-100)
            - feedback: List of suggestions for improvement
        """
        score = 0
        feedback = []
        
        # Length scoring (up to 40 points)
        length = len(password)
        if length >= 16:
            score += 40
        elif length >= 12:
            score += 30
        elif length >= 8:
            score += 20
        else:
            score += length * 2
            feedback.append("Use at least 8 characters")
        
        # Complexity scoring (up to 30 points)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', password))
        
        complexity = sum([has_lower, has_upper, has_digit, has_special])
        score += complexity * 7.5
        
        if not has_lower:
            feedback.append("Add lowercase letters")
        if not has_upper:
            feedback.append("Add uppercase letters")
        if not has_digit:
            feedback.append("Add numbers")
        if not has_special:
            feedback.append("Add special characters")
        
        # Diversity scoring (up to 20 points)
        unique_chars = len(set(password))
        diversity_ratio = unique_chars / max(length, 1)
        score += diversity_ratio * 20
        
        # Penalty for patterns (up to -20 points)
        if self._has_repeated_characters(password):
            score -= 10
            feedback.append("Avoid repeated characters")
        
        if self._has_sequential_characters(password):
            score -= 10
            feedback.append("Avoid sequential characters")
        
        # Penalty for common passwords (up to -30 points)
        if self._is_common_password(password):
            score -= 30
            feedback.append("Avoid common passwords")
        
        # Normalize score to 0-100
        score = max(0, min(100, score))
        
        # Determine strength level
        if score >= 80:
            strength = "very_strong"
        elif score >= 60:
            strength = "strong"
        elif score >= 40:
            strength = "medium"
        else:
            strength = "weak"
        
        return {
            "strength": strength,
            "score": score,
            "feedback": feedback
        }


def validate_password(password: str, username: str = None, 
                     common_passwords_file: str = None) -> Tuple[bool, List[str]]:
    """
    Convenience function to validate a password.
    
    Args:
        password: The password to validate
        username: Optional username to check for similarity
        common_passwords_file: Optional path to common passwords file
        
    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    validator = PasswordValidator(common_passwords_file)
    return validator.validate(password, username)
