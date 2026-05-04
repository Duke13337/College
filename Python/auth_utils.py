"""Хэширование паролей без внешних зависимостей (PBKDF2-HMAC-SHA256)."""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 390_000
_SCHEME_PREFIX = "pbkdf2_sha256"


def hash_password(plain: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt.encode("ascii"), _ITERATIONS)
    return f"{_SCHEME_PREFIX}${salt}${_ITERATIONS}${dk.hex()}"


def verify_password(plain: str, stored: str | None) -> bool:
    if not stored or not plain:
        return False
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != _SCHEME_PREFIX:
        return False
    _, salt, it_s, expected_hex = parts
    try:
        iterations = int(it_s)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt.encode("ascii"), iterations)
    try:
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    return hmac.compare_digest(dk, expected)
