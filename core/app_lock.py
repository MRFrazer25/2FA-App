"""Unlocking the app.

Token secrets are encrypted with a random data key. The data key is stored in the
keyring encrypted ("wrapped") with a key derived from the user's PIN or password,
so the secrets can only be read after the correct PIN or password is entered.
Changing the PIN or password only re-wraps the data key.
"""
import base64
import hashlib
import hmac
import json
import keyring
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SERVICE_NAME = "Python2FAApp_Lock"
VAULT_KEY = "vault_key"

KIND_PIN = "pin"
KIND_PASSWORD = "password"
MIN_PIN_LENGTH = 6
MIN_PASSWORD_LENGTH = 8

# OWASP recommended scrypt parameters (about 1 second and 128 MiB per attempt)
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
DATA_KEY_SIZE_BYTES = 32 # AES-256
NONCE_SIZE_BYTES = 12
WRAP_ASSOCIATED_DATA = b"2FA App data key"

# Before encryption was added, only a hash of the PIN was stored
LEGACY_PIN_HASH_KEY = "app_pin_hash"
LEGACY_SALT_KEY = "app_pin_salt"
LEGACY_PBKDF2_ITERATIONS = 100000
LEGACY_PIN_RECORD_PREFIX = "pbkdf2_sha256"

def describe(kind: str) -> str:
    return "PIN" if kind == KIND_PIN else "password"

def validate_passcode(kind: str, passcode: str):
    """Raises ValueError if the PIN or password doesn't meet the requirements."""
    if kind == KIND_PIN:
        if not passcode.isdigit():
            raise ValueError("PIN must contain digits only.")
        if len(passcode) < MIN_PIN_LENGTH:
            raise ValueError(f"PIN must be at least {MIN_PIN_LENGTH} digits.")
    elif kind == KIND_PASSWORD:
        if len(passcode) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    else:
        raise ValueError("Unknown passcode type.")

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _derive_wrapping_key(passcode: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=DATA_KEY_SIZE_BYTES, n=n, r=r, p=p).derive(passcode.encode("utf-8"))

def _load_vault_record() -> dict | None:
    stored = keyring.get_password(SERVICE_NAME, VAULT_KEY)
    return json.loads(stored) if stored else None

def has_vault() -> bool:
    """Checks if a PIN or password has been set up. Keyring errors are raised so a failed
    read is never treated as "not set up"."""
    return _load_vault_record() is not None

def passcode_kind() -> str:
    """Returns KIND_PIN or KIND_PASSWORD for the current vault."""
    record = _load_vault_record()
    return record.get("kind", KIND_PASSWORD) if record else KIND_PASSWORD

def set_passcode(data_key: bytes, kind: str, passcode: str):
    """Stores the data key wrapped with a key derived from the given PIN or password,
    replacing any previous one, and removes any legacy PIN hash."""
    validate_passcode(kind, passcode)
    salt = os.urandom(16)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    wrapping_key = _derive_wrapping_key(passcode, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    record = {
        "version": 1,
        "kind": kind,
        "kdf": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "wrapped_key": _b64(AESGCM(wrapping_key).encrypt(nonce, data_key, WRAP_ASSOCIATED_DATA)),
    }
    keyring.set_password(SERVICE_NAME, VAULT_KEY, json.dumps(record))
    _delete_legacy_pin()

def create_vault(kind: str, passcode: str) -> bytes:
    """Creates a new random data key protected by the given PIN or password and returns it."""
    data_key = AESGCM.generate_key(bit_length=DATA_KEY_SIZE_BYTES * 8)
    set_passcode(data_key, kind, passcode)
    return data_key

def unlock(passcode: str) -> bytes | None:
    """Returns the data key if the PIN or password is correct, otherwise None.
    Keyring errors are raised."""
    record = _load_vault_record()
    if record is None:
        return None
    wrapping_key = _derive_wrapping_key(passcode, base64.b64decode(record["salt"]),
                                        record["n"], record["r"], record["p"])
    try:
        return AESGCM(wrapping_key).decrypt(base64.b64decode(record["nonce"]),
                                            base64.b64decode(record["wrapped_key"]),
                                            WRAP_ASSOCIATED_DATA)
    except InvalidTag:
        return None

# Legacy PIN (hash only, from before encryption was added)

def _load_legacy_pin_record() -> tuple[int, bytes, bytes] | None:
    """Returns (iterations, salt, hash) for a legacy PIN, or None if there isn't one."""
    stored = keyring.get_password(SERVICE_NAME, LEGACY_PIN_HASH_KEY)
    if not stored:
        return None
    if stored.startswith(LEGACY_PIN_RECORD_PREFIX + "$"):
        _, iterations, salt_hex, hash_hex = stored.split("$")
        return int(iterations), bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
    salt_hex = keyring.get_password(SERVICE_NAME, LEGACY_SALT_KEY)
    if not salt_hex:
        return None
    return LEGACY_PBKDF2_ITERATIONS, bytes.fromhex(salt_hex), bytes.fromhex(stored)

def has_legacy_pin() -> bool:
    return _load_legacy_pin_record() is not None

def verify_legacy_pin(pin: str) -> bool:
    record = _load_legacy_pin_record()
    if record is None:
        return False
    iterations, salt, stored_hash = record
    attempt = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(attempt, stored_hash)

def legacy_pin_kind(pin: str) -> str | None:
    """Returns the kind a legacy PIN can be kept as under the current rules, or None if it's too weak."""
    for kind in (KIND_PIN, KIND_PASSWORD):
        try:
            validate_passcode(kind, pin)
            return kind
        except ValueError:
            pass
    return None

def _delete_legacy_pin():
    for key in (LEGACY_PIN_HASH_KEY, LEGACY_SALT_KEY):
        try:
            keyring.delete_password(SERVICE_NAME, key)
        except keyring.errors.PasswordDeleteError:
            pass
