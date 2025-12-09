# utils/password.py
def check_password_strength(password: str) -> str:
   
    # Check password strength
    uppercase = any(char.isupper() for char in password)
    lowercase = any(char.islower() for char in password)
    digit = any(char.isdigit() for char in password)
    special_char = any(char in "!@#$%^&*()" for char in password)

    if len(password) >= 8 and uppercase and lowercase and digit and special_char:
        return "Strong"
    elif len(password) >= 8 and ((uppercase and lowercase and digit) or special_char):
        return "Moderate"
    else:
        return "Weak"
