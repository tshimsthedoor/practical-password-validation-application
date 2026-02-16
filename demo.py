#!/usr/bin/env python3
"""
Password Validator Demo

This script demonstrates the password validation functionality with various examples.
"""

from password_validator import PasswordValidator


def print_result(password, username=None):
    """Print validation result for a password."""
    validator = PasswordValidator("common_passwords.txt")
    is_valid, issues = validator.validate(password, username)
    strength = validator.get_password_strength(password)
    
    print(f"\n{'='*70}")
    print(f"Password: {password}")
    if username:
        print(f"Username: {username}")
    print(f"{'='*70}")
    print(f"Valid: {is_valid}")
    print(f"Strength: {strength['strength']} (Score: {strength['score']}/100)")
    
    if issues:
        print("\nIssues found:")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
    
    if strength['feedback']:
        print("\nSuggestions:")
        for i, feedback in enumerate(strength['feedback'], 1):
            print(f"  {i}. {feedback}")
    
    if is_valid:
        print("\n✓ This password passes all security checks!")
    else:
        print("\n✗ This password does not meet security requirements.")


def main():
    """Run demo examples."""
    print("=" * 70)
    print("PASSWORD VALIDATOR DEMO - OWASP Compliant")
    print("=" * 70)
    
    # Example 1: Strong password
    print("\n\n### Example 1: Strong, Valid Password ###")
    print_result("MySecure!P@ssw0rd2024")
    
    # Example 2: Weak password - too short
    print("\n\n### Example 2: Too Short ###")
    print_result("Pass1!")
    
    # Example 3: Common password
    print("\n\n### Example 3: Common Password ###")
    print_result("password123")
    
    # Example 4: Missing complexity
    print("\n\n### Example 4: Missing Uppercase ###")
    print_result("mypassword123!")
    
    # Example 5: Repeated characters
    print("\n\n### Example 5: Repeated Characters ###")
    print_result("Passssword123!")
    
    # Example 6: Sequential characters
    print("\n\n### Example 6: Sequential Characters ###")
    print_result("Abc12345!Pass")
    
    # Example 7: Similar to username
    print("\n\n### Example 7: Similar to Username ###")
    print_result("JohnSmith123!", username="johnsmith")
    
    # Example 8: Very strong password
    print("\n\n### Example 8: Very Strong Password ###")
    print_result("C0mpl3x!Secur3#P@ssw0rd$2024")
    
    # Example 9: Password with whitespace
    print("\n\n### Example 9: Password with Whitespace ###")
    print_result(" MyPassword123! ")
    
    print("\n\n" + "=" * 70)
    print("Demo completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()
