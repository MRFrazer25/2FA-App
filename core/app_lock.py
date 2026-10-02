"""Unlocking the app.

Token secrets are encrypted with a random data key. The data key is stored in the
keyring encrypted ("wrapped") with a key derived from the user's PIN or password,
so the secrets can only be read after the correct PIN or password is entered.

Changing the PIN or password also replaces the data key, so an old copy of the
keyring plus the old PIN or password can't decrypt tokens saved afterwards. While
tokens are being moved to the new key, the vault holds both keys (wrapped with the
new PIN or password); the next unlock finishes the move if it was interrupted.

Wrong attempts are counted in the keyring, so the lockout survives restarts.
"""
import base64
import hashlib
import hmac
import json
import keyring
import math
import os
import time
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from core import secure_storage
from core.secure_storage import DataKeys

SERVICE_NAME = "Python2FAApp_Lock"
VAULT_KEY = "vault_key"
LOCKOUT_KEY = "lockout"

KIND_PIN = "pin"
KIND_PASSWORD = "password"
MIN_PIN_LENGTH = 6
MIN_PASSWORD_LENGTH = 8

# OWASP recommended scrypt parameters (about 1 second and 128 MiB per attempt)
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
NONCE_SIZE_BYTES = 12
WRAP_ASSOCIATED_DATA = b"2FA App data key "

# After this many wrong attempts in a row, each further wrong attempt starts a wait that
# doubles from LOCKOUT_BASE_SECONDS, capped so a mistyping prankster can't lock you out for long
FAILURES_BEFORE_LOCKOUT = 3
LOCKOUT_BASE_SECONDS = 30
MAX_LOCKOUT_SECONDS = 15 * 60

# Before encryption was added, only a hash of the PIN was stored
LEGACY_PIN_HASH_KEY = "app_pin_hash"
LEGACY_SALT_KEY = "app_pin_salt"
LEGACY_PBKDF2_ITERATIONS = 100000
LEGACY_PIN_RECORD_PREFIX = "pbkdf2_sha256"

class LockedOutError(Exception):
    """Raised when unlocking is attempted during a lockout."""
    def __init__(self, seconds: int):
        super().__init__(f"Too many incorrect attempts. Try again in {format_wait(seconds)}.")
        self.seconds = seconds

def describe(kind: str) -> str:
    return "PIN" if kind == KIND_PIN else "password"

def format_wait(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes} min {seconds:02d} s"

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

# Lockout

def _load_lockout() -> tuple[int, float]:
    """Returns (failed attempts in a row, time the lockout ends). Keyring errors are raised."""
    stored = keyring.get_password(SERVICE_NAME, LOCKOUT_KEY)
    if not stored:
        return 0, 0.0
    try:
        data = json.loads(stored)
        return int(data["failures"]), float(data["locked_until"])
    except (ValueError, TypeError, KeyError):
        # Unreadable, so start over. Anyone able to edit it could also just delete it.
        return 0, 0.0

def seconds_locked_out() -> int:
    """Seconds until unlocking may be tried again, or 0 if it can be tried now."""
    _, locked_until = _load_lockout()
    # Capped so moving the clock back can't extend the wait
    remaining = min(locked_until - time.time(), MAX_LOCKOUT_SECONDS)
    return max(0, math.ceil(remaining))

def attempts_before_lockout() -> int:
    """Wrong attempts left before the next one starts a wait."""
    failures, _ = _load_lockout()
    return max(0, FAILURES_BEFORE_LOCKOUT - failures)

def _check_lockout():
    seconds = seconds_locked_out()
    if seconds:
        raise LockedOutError(seconds)

def _record_failed_attempt():
    failures, _ = _load_lockout()
    failures += 1
    locked_until = 0.0
    if failures >= FAILURES_BEFORE_LOCKOUT:
        doublings = min(failures - FAILURES_BEFORE_LOCKOUT, 32) # Avoid huge numbers; the cap applies long before
        wait = min(LOCKOUT_BASE_SECONDS * 2 ** doublings, MAX_LOCKOUT_SECONDS)
        locked_until = time.time() + wait
    keyring.set_password(SERVICE_NAME, LOCKOUT_KEY, json.dumps({"failures": failures, "locked_until": locked_until}))

def _reset_failed_attempts():
    _delete_entry(LOCKOUT_KEY)

# Vault (the data keys, wrapped with the PIN or password)

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _derive_wrapping_key(passcode: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passcode.encode("utf-8"))

def _load_vault_record() -> dict | None:
    stored = keyring.get_password(SERVICE_NAME, VAULT_KEY)
    return json.loads(stored) if stored else None

def _write_vault(kind: str, wrapping_key: bytes, salt: bytes, params: tuple[int, int, int], data_keys: DataKeys):
    """Stores every data key wrapped with the wrapping key, in a single keyring write."""
    wrapped_keys = {}
    for key_id, key in data_keys.keys.items():
        nonce = os.urandom(NONCE_SIZE_BYTES)
        wrapped = AESGCM(wrapping_key).encrypt(nonce, key, WRAP_ASSOCIATED_DATA + key_id.encode("ascii"))
        wrapped_keys[key_id] = {"nonce": _b64(nonce), "wrapped": _b64(wrapped)}
    n, r, p = params
    record = {
        "version": 1,
        "kind": kind,
        "kdf": "scrypt",
        "n": n,
        "r": r,
        "p": p,
        "salt": _b64(salt),
        "current": data_keys.current_id,
        "keys": wrapped_keys,
    }
    keyring.set_password(SERVICE_NAME, VAULT_KEY, json.dumps(record))

def _unwrap_keys(record: dict, wrapping_key: bytes) -> DataKeys:
    """Raises InvalidTag if the wrapping key (i.e. the PIN or password) is wrong."""
    keys = {}
    for key_id, wrapped in record["keys"].items():
        keys[key_id] = AESGCM(wrapping_key).decrypt(base64.b64decode(wrapped["nonce"]),
                                                    base64.b64decode(wrapped["wrapped"]),
                                                    WRAP_ASSOCIATED_DATA + key_id.encode("ascii"))
    return DataKeys(keys, record["current"])

def _only_current(data_keys: DataKeys) -> DataKeys:
    return DataKeys({data_keys.current_id: data_keys.current_key}, data_keys.current_id)

def _move_tokens_to_current_key(kind, wrapping_key, salt, params, data_keys: DataKeys) -> DataKeys:
    """Re-encrypts tokens still on older keys, then removes those keys from the vault.
    If interrupted, the vault still holds every key and the next unlock tries again."""
    secure_storage.set_data_keys(data_keys)
    secure_storage.reencrypt_outdated_tokens()
    final_keys = _only_current(data_keys)
    _write_vault(kind, wrapping_key, salt, params, final_keys)
    secure_storage.set_data_keys(final_keys)
    return final_keys

def has_vault() -> bool:
    """Checks if a PIN or password has been set up. Keyring errors are raised so a failed
    read is never treated as "not set up"."""
    return _load_vault_record() is not None

def passcode_kind() -> str:
    """Returns KIND_PIN or KIND_PASSWORD for the current vault."""
    record = _load_vault_record()
    return record.get("kind", KIND_PASSWORD) if record else KIND_PASSWORD

def create_vault(kind: str, passcode: str) -> DataKeys:
    """Creates a new random data key protected by the given PIN or password and returns it.
    Any legacy PIN hash is removed."""
    validate_passcode(kind, passcode)
    data_keys = secure_storage.new_data_keys()
    salt = os.urandom(16)
    params = (SCRYPT_N, SCRYPT_R, SCRYPT_P)
    _write_vault(kind, _derive_wrapping_key(passcode, salt, *params), salt, params, data_keys)
    _reset_failed_attempts()
    _delete_legacy_pin()
    return data_keys

def unlock(passcode: str) -> DataKeys | None:
    """Returns the data keys if the PIN or password is correct, otherwise None.

    Raises:
        LockedOutError: If too many wrong attempts were made recently.
        Keyring errors.
    """
    record = _load_vault_record()
    if record is None:
        return None
    _check_lockout()
    salt = base64.b64decode(record["salt"])
    params = (record["n"], record["r"], record["p"])
    wrapping_key = _derive_wrapping_key(passcode, salt, *params)
    try:
        data_keys = _unwrap_keys(record, wrapping_key)
    except InvalidTag:
        _record_failed_attempt()
        return None
    _reset_failed_attempts()

    if len(data_keys.keys) > 1:
        # A change of PIN or password was interrupted before every token moved to the new key
        try:
            return _move_tokens_to_current_key(record["kind"], wrapping_key, salt, params, data_keys)
        except Exception as e:
            print(f"Could not finish moving tokens to the new key, will retry on next unlock: {e}")
    return data_keys

def change_passcode(data_keys: DataKeys, kind: str, passcode: str) -> DataKeys:
    """Sets a new PIN or password and moves every token to a new data key.
    data_keys must be the currently unlocked keys. Returns the new data keys, which are also
    made active in secure_storage."""
    validate_passcode(kind, passcode)
    new_keys = secure_storage.new_data_keys()
    staged_keys = DataKeys({**data_keys.keys, **new_keys.keys}, new_keys.current_id)
    salt = os.urandom(16)
    params = (SCRYPT_N, SCRYPT_R, SCRYPT_P)
    wrapping_key = _derive_wrapping_key(passcode, salt, *params)

    # From this write on only the new PIN or password works; old keys stay until tokens move
    _write_vault(kind, wrapping_key, salt, params, staged_keys)
    try:
        return _move_tokens_to_current_key(kind, wrapping_key, salt, params, staged_keys)
    except Exception as e:
        # The new PIN or password is already in effect and every token is still readable
        print(f"Could not finish moving tokens to the new key, will retry on next unlock: {e}")
        secure_storage.set_data_keys(staged_keys)
        return staged_keys

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
    """Checks a legacy PIN, with the same lockout as unlock()."""
    record = _load_legacy_pin_record()
    if record is None:
        return False
    _check_lockout()
    iterations, salt, stored_hash = record
    attempt = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, iterations)
    if not hmac.compare_digest(attempt, stored_hash):
        _record_failed_attempt()
        return False
    _reset_failed_attempts()
    return True

def legacy_pin_kind(pin: str) -> str | None:
    """Returns the kind a legacy PIN can be kept as under the current rules, or None if it's too weak."""
    for kind in (KIND_PIN, KIND_PASSWORD):
        try:
            validate_passcode(kind, pin)
            return kind
        except ValueError:
            pass
    return None

def _delete_entry(key: str):
    try:
        keyring.delete_password(SERVICE_NAME, key)
    except keyring.errors.PasswordDeleteError:
        pass

def _delete_legacy_pin():
    for key in (LEGACY_PIN_HASH_KEY, LEGACY_SALT_KEY):
        _delete_entry(key)
