"""
Usage Examples for Password Validator

This file demonstrates various use cases for the password validator.
"""

from password_validator import PasswordValidator, validate_password


def example_1_basic_usage():
    """Example 1: Basic password validation."""
    print("=" * 60)
    print("Example 1: Basic Password Validation")
    print("=" * 60)
    
    validator = PasswordValidator("common_passwords.txt")
    
    passwords = [
        "MySecure!P@ss2024",  # Valid
        "weak",                # Too short
        "password",            # Common password
    ]
    
    for pwd in passwords:
        is_valid, issues = validator.validate(pwd)
        print(f"\nPassword: {pwd}")
        print(f"Valid: {is_valid}")
        if issues:
            print(f"Issues: {', '.join(issues)}")


def example_2_with_username():
    """Example 2: Validation with username checking."""
    print("\n\n" + "=" * 60)
    print("Example 2: Username Similarity Checking")
    print("=" * 60)
    
    validator = PasswordValidator("common_passwords.txt")
    
    username = "johnsmith"
    passwords = [
        ("SecurePass123!", "Should pass"),
        ("johnsmith123!", "Contains username"),
        ("JohnSmith!@#", "Similar to username"),
    ]
    
    for pwd, description in passwords:
        is_valid, issues = validator.validate(pwd, username=username)
        print(f"\nPassword: {pwd} ({description})")
        print(f"Username: {username}")
        print(f"Valid: {is_valid}")
        if issues:
            print(f"Issues: {', '.join(issues)}")


def example_3_strength_assessment():
    """Example 3: Password strength assessment."""
    print("\n\n" + "=" * 60)
    print("Example 3: Password Strength Assessment")
    print("=" * 60)
    
    validator = PasswordValidator()
    
    passwords = [
        "Pass1!",
        "Password123!",
        "MyStr0ng!P@ssw0rd",
        "C0mpl3x!Secur3#P@ssw0rd$2024",
    ]
    
    for pwd in passwords:
        result = validator.get_password_strength(pwd)
        print(f"\nPassword: {pwd}")
        print(f"Strength: {result['strength']}")
        print(f"Score: {result['score']:.1f}/100")
        if result['feedback']:
            print(f"Feedback: {', '.join(result['feedback'])}")


def example_4_convenience_function():
    """Example 4: Using the convenience function."""
    print("\n\n" + "=" * 60)
    print("Example 4: Convenience Function")
    print("=" * 60)
    
    # Quick one-liner validation
    is_valid, issues = validate_password(
        password="MySecure!Pass123",
        username="testuser",
        common_passwords_file="common_passwords.txt"
    )
    
    print(f"\nPassword: MySecure!Pass123")
    print(f"Username: testuser")
    print(f"Valid: {is_valid}")
    print(f"Issues: {issues if issues else 'None'}")


def example_5_integration():
    """Example 5: Integration with user registration."""
    print("\n\n" + "=" * 60)
    print("Example 5: User Registration Integration")
    print("=" * 60)
    
    def register_user(username, password):
        """Simulate user registration with password validation."""
        validator = PasswordValidator("common_passwords.txt")
        
        # Validate password
        is_valid, issues = validator.validate(password, username=username)
        
        if not is_valid:
            return {
                "success": False,
                "message": "Password does not meet requirements",
                "errors": issues
            }
        
        # Check strength
        strength = validator.get_password_strength(password)
        
        # Warn if password is weak
        if strength['strength'] in ['weak', 'medium']:
            return {
                "success": True,
                "message": "User registered successfully",
                "warning": f"Password strength is {strength['strength']}. Consider using a stronger password.",
                "suggestions": strength['feedback']
            }
        
        return {
            "success": True,
            "message": "User registered successfully with strong password"
        }
    
    # Test cases
    test_users = [
        ("alice", "SecureP@ss123!"),
        ("bob", "password"),
        ("charlie", "charlie123!"),
    ]
    
    for username, password in test_users:
        print(f"\nRegistering user: {username}")
        result = register_user(username, password)
        print(f"Success: {result['success']}")
        print(f"Message: {result['message']}")
        if 'errors' in result:
            print(f"Errors: {len(result['errors'])} found")
        if 'warning' in result:
            print(f"Warning: {result['warning']}")


def example_6_batch_validation():
    """Example 6: Batch password validation."""
    print("\n\n" + "=" * 60)
    print("Example 6: Batch Password Validation")
    print("=" * 60)
    
    validator = PasswordValidator("common_passwords.txt")
    
    # Simulate checking multiple passwords from a leaked database
    leaked_passwords = [
        "password123",
        "admin",
        "qwerty",
        "SecureP@ss2024!",
        "test123",
    ]
    
    results = []
    for pwd in leaked_passwords:
        is_valid, issues = validator.validate(pwd)
        strength = validator.get_password_strength(pwd)
        results.append({
            "password": pwd,
            "is_valid": is_valid,
            "strength": strength['strength'],
            "score": strength['score']
        })
    
    print(f"\nAnalyzed {len(leaked_passwords)} passwords:")
    print(f"\n{'Password':<20} {'Valid':<10} {'Strength':<15} {'Score':<10}")
    print("-" * 60)
    for result in results:
        print(f"{result['password']:<20} {str(result['is_valid']):<10} "
              f"{result['strength']:<15} {result['score']:<10.1f}")


if __name__ == "__main__":
    example_1_basic_usage()
    example_2_with_username()
    example_3_strength_assessment()
    example_4_convenience_function()
    example_5_integration()
    example_6_batch_validation()
    
    print("\n\n" + "=" * 60)
    print("All examples completed!")
    print("=" * 60)
