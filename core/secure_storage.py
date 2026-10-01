import base64
import binascii
import json
import keyring
import os
import uuid
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core import otp

SERVICE_NAME = "2FA App"

# For storing the list of account identifiers
ACCOUNTS_LIST_KEY = "__accounts_list__"
AUTO_LOCK_SETTING_KEY = "__auto_lock_timeout_seconds__"
DEFAULT_AUTO_LOCK_SECONDS = 300 # 5 minutes

# Windows Credential Manager rejects values longer than 1280 characters, so larger values
# are split across several entries. json.dumps escapes non-ASCII text, so every character
# stored is a single UTF-16 code unit.
MAX_ENTRY_CHARS = 1000
CHUNKS_MARKER = "__chunks__"

MIN_SECRET_LENGTH = 16 # 80 bits, the shortest secret commonly issued by services
ENCRYPTED_TOKEN_VERSION = 2
NONCE_SIZE_BYTES = 12

# Key that encrypts token data. Only held in memory while the app is unlocked.
_data_key = None

class LockedError(RuntimeError):
    """Raised when token data is accessed while the app is locked."""

def set_data_key(data_key: bytes):
    global _data_key
    _data_key = data_key

def clear_data_key():
    global _data_key
    _data_key = None

def _require_data_key() -> bytes:
    if _data_key is None:
        raise LockedError("The app is locked.")
    return _data_key

def normalize_secret_key(secret_key: str) -> str:
    """Returns the secret as unpadded uppercase Base32.

    Raises:
        ValueError: If the secret is too short or is not valid Base32.
    """
    normalized = secret_key.replace(" ", "").upper().rstrip("=")
    if len(normalized) < MIN_SECRET_LENGTH:
        raise ValueError(f"Secret key must be at least {MIN_SECRET_LENGTH} Base32 characters (e.g. JBSWY3DPEHPK3PXP).")
    try:
        base64.b32decode(normalized + "=" * (-len(normalized) % 8))
    except binascii.Error:
        raise ValueError("Secret key is not valid Base32 (letters A-Z and digits 2-7 only).")
    return normalized

def _chunk_key(key: str, index: int) -> str:
    return f"{key}#{index}"

def _stored_chunk_count(key: str) -> int:
    """Returns how many extra chunk entries the value stored under key uses."""
    raw = keyring.get_password(SERVICE_NAME, key)
    if raw is None:
        return 0
    try:
        value = json.loads(raw)
    except ValueError:
        return 0
    if isinstance(value, dict) and CHUNKS_MARKER in value:
        return int(value[CHUNKS_MARKER])
    return 0

def _read_value(key: str):
    """Reads and decodes a JSON value, reassembling it if it was split into chunks.
    Returns None if nothing is stored. Keyring and decoding errors are raised."""
    raw = keyring.get_password(SERVICE_NAME, key)
    if raw is None:
        return None
    value = json.loads(raw)
    if isinstance(value, dict) and CHUNKS_MARKER in value:
        parts = []
        for index in range(1, int(value[CHUNKS_MARKER]) + 1):
            part = keyring.get_password(SERVICE_NAME, _chunk_key(key, index))
            if part is None:
                raise ValueError("A stored value is missing one of its parts.")
            parts.append(part)
        value = json.loads("".join(parts))
    return value

def _write_value(key: str, value):
    """Encodes and stores a JSON value, splitting it into chunks if it is too long for one entry."""
    text = json.dumps(value)
    old_chunk_count = _stored_chunk_count(key)

    if len(text) <= MAX_ENTRY_CHARS:
        keyring.set_password(SERVICE_NAME, key, text)
        new_chunk_count = 0
    else:
        parts = [text[i:i + MAX_ENTRY_CHARS] for i in range(0, len(text), MAX_ENTRY_CHARS)]
        for index, part in enumerate(parts, start=1):
            keyring.set_password(SERVICE_NAME, _chunk_key(key, index), part)
        keyring.set_password(SERVICE_NAME, key, json.dumps({CHUNKS_MARKER: len(parts)}))
        new_chunk_count = len(parts)

    # Remove chunks left over from a previous, longer value
    for index in range(new_chunk_count + 1, old_chunk_count + 1):
        _delete_entry(_chunk_key(key, index))

def _delete_entry(key: str):
    try:
        keyring.delete_password(SERVICE_NAME, key)
    except keyring.errors.PasswordDeleteError:
        pass # Already gone

def _delete_value(key: str):
    """Deletes a value and any chunks it was split into."""
    chunk_count = _stored_chunk_count(key)
    _delete_entry(key)
    for index in range(1, chunk_count + 1):
        _delete_entry(_chunk_key(key, index))

def _encrypt_token(identifier: str, data: dict) -> dict:
    """Encrypts token data. The identifier is authenticated too, so an encrypted
    entry can't be swapped in under another token's identifier."""
    nonce = os.urandom(NONCE_SIZE_BYTES)
    ciphertext = AESGCM(_require_data_key()).encrypt(nonce, json.dumps(data).encode("utf-8"), identifier.encode("utf-8"))
    return {
        "v": ENCRYPTED_TOKEN_VERSION,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }

def _is_encrypted(stored: dict) -> bool:
    return isinstance(stored, dict) and "ct" in stored

def _decrypt_token(identifier: str, stored: dict) -> dict:
    """Returns the token data from a stored entry, decrypting it if needed.
    Entries saved before encryption was added are returned as-is."""
    if not _is_encrypted(stored):
        return stored
    plaintext = AESGCM(_require_data_key()).decrypt(base64.b64decode(stored["nonce"]),
                                                    base64.b64decode(stored["ct"]),
                                                    identifier.encode("utf-8"))
    return json.loads(plaintext)

def save_token_secret(account_name: str, issuer_name: str, secret_key: str, identifier: str = None, recovery_codes: str = None,
                      digits: int = otp.DEFAULT_DIGITS, period: int = otp.DEFAULT_PERIOD, algorithm: str = otp.DEFAULT_ALGORITHM) -> str:
    """Encrypts and saves a token. If an identifier is provided, it updates that existing token.
    Otherwise, a new token is created.

    Args:
        account_name: The name of the account (e.g., user's email or username).
        issuer_name: The name of the service or issuer (e.g., "Google", "GitHub").
        secret_key: The Base32 encoded secret key for OTP generation.
        identifier: Optional. The existing identifier of the token to update.
                    If None, a new token is created and a new identifier generated.
        recovery_codes: Optional. The recovery codes for the token.
        digits: Code length (6, 7, or 8).
        period: Seconds each code is valid for.
        algorithm: Hash algorithm ("SHA1", "SHA256", or "SHA512").

    Returns:
        The identifier (new or existing) of the saved token.

    Raises:
        ValueError: If a field is empty or invalid.
        LockedError: If the app is locked.
    """
    if not account_name or not secret_key or not issuer_name:
        raise ValueError("Account name, issuer name, and secret key cannot be empty.")
    secret_key = normalize_secret_key(secret_key)
    otp.validate_settings(digits, period, algorithm)
    _require_data_key()

    data = {
        "account_name": account_name,
        "issuer_name": issuer_name,
        "secret_key": secret_key,
        "recovery_codes": recovery_codes,
        "digits": digits,
        "period": period,
        "algorithm": algorithm,
    }
    is_new_token = identifier is None
    try:
        accounts = get_all_token_identifiers()
        if is_new_token:
            # Random identifiers keep account and service names out of the keyring entry names
            identifier = uuid.uuid4().hex

        _write_value(identifier, _encrypt_token(identifier, data))
        try:
            if identifier not in accounts:
                accounts.append(identifier)
                _write_value(ACCOUNTS_LIST_KEY, accounts)
        except Exception:
            # Don't leave a secret behind that the app can't list or delete
            if is_new_token:
                try:
                    _delete_value(identifier)
                except Exception:
                    pass
            raise
        return identifier
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Secure storage is unavailable.")
        raise
    except Exception as e:
        print(f"Error saving secret: {e}")
        raise

def get_token_secret(identifier: str) -> dict | None:
    """Retrieves and decrypts the data for a given token identifier.
    Returns None if the token doesn't exist or can't be read or decrypted.

    Raises:
        LockedError: If the app is locked.
    """
    _require_data_key()
    try:
        stored = _read_value(identifier)
        if not stored:
            return None
        data = _decrypt_token(identifier, stored)
        return {
            "identifier": identifier,
            "account_name": data.get("account_name"),
            "issuer_name": data.get("issuer_name"),
            "secret_key": data.get("secret_key"),
            "recovery_codes": data.get("recovery_codes") or "",
            "digits": data.get("digits", otp.DEFAULT_DIGITS),
            "period": data.get("period", otp.DEFAULT_PERIOD),
            "algorithm": data.get("algorithm", otp.DEFAULT_ALGORITHM),
        }
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Secure storage is unavailable.")
        return None
    except InvalidTag:
        print("Error retrieving secret: a token could not be decrypted.")
        return None
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None

def migrate_plaintext_tokens() -> int:
    """Encrypts any tokens saved before encryption was added, moving each to a new random
    identifier. Returns how many tokens were migrated.

    The encrypted copies are written before the account list is switched over, and the
    plaintext entries are only deleted after that, so an interruption never loses a token.
    """
    _require_data_key()
    accounts = get_all_token_identifiers()
    new_accounts = []
    replaced = []
    for identifier in accounts:
        stored = _read_value(identifier)
        if stored is None or _is_encrypted(stored):
            new_accounts.append(identifier)
            continue
        new_identifier = uuid.uuid4().hex
        _write_value(new_identifier, _encrypt_token(new_identifier, stored))
        new_accounts.append(new_identifier)
        replaced.append(identifier)

    if replaced:
        _write_value(ACCOUNTS_LIST_KEY, new_accounts)
        for identifier in replaced:
            _delete_value(identifier)
    return len(replaced)

def delete_token_secret(identifier: str):
    """Deletes the token secret for a given identifier and removes it from the account list.
    Keyring errors are raised."""
    _delete_value(identifier)
    accounts = get_all_token_identifiers()
    if identifier in accounts:
        accounts.remove(identifier)
        _write_value(ACCOUNTS_LIST_KEY, accounts)

def get_all_token_identifiers() -> list[str]:
    """Retrieves the list of all account identifiers stored.
    Keyring errors are raised rather than returning an empty list, so a failed read
    can never be mistaken for "no tokens" and written back over the real list."""
    return _read_value(ACCOUNTS_LIST_KEY) or []

def save_auto_lock_setting(timeout_seconds: int):
    """Saves the auto-lock timeout in seconds."""
    try:
        keyring.set_password(SERVICE_NAME, AUTO_LOCK_SETTING_KEY, str(timeout_seconds))
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Cannot save auto-lock setting.")
    except Exception as e:
        print(f"Error saving auto-lock setting: {e}")

def get_auto_lock_setting() -> int:
    """Retrieves the auto-lock timeout in seconds. Returns default if not set or error."""
    try:
        timeout_str = keyring.get_password(SERVICE_NAME, AUTO_LOCK_SETTING_KEY)
        if timeout_str is not None:
            return int(timeout_str)
    except keyring.errors.NoKeyringError:
        pass
    except Exception as e:
        print(f"Error retrieving auto-lock setting: {e}. Using default.")
    return DEFAULT_AUTO_LOCK_SECONDS # Default value

def get_all_token_data() -> list[dict]:
    """
    Retrieves and decrypts the data for every stored token.
    Returns a list of dictionaries, where each dictionary represents a token.
    Raises if the account list can't be read or the app is locked.
    """
    all_data = []
    for identifier in get_all_token_identifiers():
        token_info = get_token_secret(identifier)
        if token_info and token_info.get("account_name") and token_info.get("secret_key") and token_info.get("issuer_name"):
            all_data.append(token_info)
        else:
            print("[secure_storage] Warning: Skipping a token during list retrieval due to missing critical data.")
    return all_data
