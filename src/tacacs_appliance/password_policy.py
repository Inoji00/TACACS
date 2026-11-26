"""Policy for setting human account passwords."""

from secrets import token_urlsafe
from string import ascii_lowercase, ascii_uppercase, digits, punctuation


def valid_new_password(password: object) -> bool:
    return (
        isinstance(password, str)
        and 12 <= len(password) <= 1024
        and all(
            any(character in group for character in password)
            for group in (ascii_uppercase, ascii_lowercase, digits, punctuation)
        )
    )


def generate_password() -> str:
    # The prefix supplies the required classes. All entropy is in the suffix.
    return "Aa1!" + token_urlsafe(48)
