# tests/test_password.py
from utils.password import check_password_strength

def test_strong_password():
    password = "Abc123!@#"
    strength = check_password_strength(password)
    
    # DEBUG PRINT
    print("=== PASSWORD STRENGTH DEBUG ===")
    print("Password:", password)
    print("Strength:", strength)
    print("===============================")
    
    assert strength == "Strong"

def test_moderate_password():
    password = "Abc12345"
    strength = check_password_strength(password)
    
    # DEBUG PRINT
    print("=== PASSWORD STRENGTH DEBUG ===")
    print("Password:", password)
    print("Strength:", strength)
    print("===============================")
    
    assert strength == "Moderate"

def test_weak_password():
    password = "abc"
    strength = check_password_strength(password)
    
    # DEBUG PRINT
    print("=== PASSWORD STRENGTH DEBUG ===")
    print("Password:", password)
    print("Strength:", strength)
    print("===============================")
    
    assert strength == "Weak"
