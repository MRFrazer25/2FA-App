"""Password-encrypted backup files (AES-256-GCM, key derived with PBKDF2-SHA256)."""
import base64
import json
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from core import otp, secure_storage

PBKDF2_ITERATIONS = 600000 # OWASP recommendation for PBKDF2-SHA256
LEGACY_PBKDF2_ITERATIONS = 390000 # Used by backups made before the iteration count was stored in the file
MAX_PBKDF2_ITERATIONS = 10000000 # Refuse backup files that would make key derivation hang
SALT_SIZE_BYTES = 16
AES_KEY_SIZE_BYTES = 32 # AES-256
AES_NONCE_SIZE_BYTES = 12 # Recommended for AES-GCM

# Token fields written to backups
BACKUP_FIELDS = ("account_name", "issuer_name", "secret_key", "recovery_codes", "digits", "period", "algorithm")

class BackupFormatError(ValueError):
    """The file isn't a valid backup."""

class BackupPasswordError(ValueError):
    """The password is wrong or the file has been modified."""

def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_backup(tokens: list[dict], password: str) -> dict:
    """Returns the contents of an encrypted backup file for the given tokens."""
    tokens_data = json.dumps([{field: token.get(field) for field in BACKUP_FIELDS} for token in tokens]).encode('utf-8')
    salt = os.urandom(SALT_SIZE_BYTES)
    nonce = os.urandom(AES_NONCE_SIZE_BYTES)
    ciphertext = AESGCM(_derive_key(password, salt, PBKDF2_ITERATIONS)).encrypt(nonce, tokens_data, None)
    return {
        "version": "1.1_encrypted",
        "kdf_iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def check_backup_format(backup_content) -> None:
    """Raises BackupFormatError if the file contents don't look like an encrypted backup."""
    if not isinstance(backup_content, dict) or \
       not all(key in backup_content for key in ["version", "salt", "nonce", "ciphertext"]):
        raise BackupFormatError("Invalid or unsupported backup file format.")
    iterations = backup_content.get("kdf_iterations", LEGACY_PBKDF2_ITERATIONS)
    if not isinstance(iterations, int) or not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise BackupFormatError("Invalid or unsupported backup file format.")

def decrypt_backup(backup_content: dict, password: str) -> list[dict]:
    """Decrypts a backup file's contents and returns its list of tokens.

    Raises:
        BackupFormatError: If the file isn't a valid backup.
        BackupPasswordError: If the password is wrong or the file was modified.
    """
    check_backup_format(backup_content)
    iterations = backup_content.get("kdf_iterations", LEGACY_PBKDF2_ITERATIONS)
    try:
        salt = base64.b64decode(backup_content["salt"])
        nonce = base64.b64decode(backup_content["nonce"])
        ciphertext = base64.b64decode(backup_content["ciphertext"])
    except (TypeError, ValueError):
        raise BackupFormatError("Invalid or unsupported backup file format.")

    try:
        tokens_data = AESGCM(_derive_key(password, salt, iterations)).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise BackupPasswordError("Invalid password or corrupted backup file. Please check the password and try again.")

    tokens = json.loads(tokens_data.decode('utf-8'))
    if not isinstance(tokens, list) or not all(isinstance(token, dict) for token in tokens):
        raise BackupFormatError("Decrypted data is not in the expected format (list of tokens).")
    return tokens

def token_fingerprint(token: dict) -> tuple:
    """Identifies a token by issuer, account, and secret, ignoring secret formatting differences."""
    secret = token.get("secret_key") or ""
    try:
        secret = secure_storage.normalize_secret_key(secret)
    except ValueError:
        pass
    return (token.get("issuer_name"), token.get("account_name"), secret)

def restore_tokens(tokens: list[dict]) -> tuple[int, int, int]:
    """Saves tokens from a backup, skipping any already stored. Tokens with missing or
    invalid fields count as failed.
    Returns (restored, skipped, failed) counts.

    Raises:
        LockedError: If the app is locked, or the PIN or password was changed since it was unlocked.
    """
    existing_tokens = {token_fingerprint(token) for token in secure_storage.get_all_token_data()}
    restored_count = skipped_count = failed_count = 0
    for token_data in tokens:
        try:
            secure_storage.check_token_fields(token_data.get("account_name"), token_data.get("issuer_name"),
                                              token_data.get("secret_key"), token_data.get("recovery_codes"))
            fingerprint = token_fingerprint(token_data)
            if fingerprint in existing_tokens:
                skipped_count += 1
                continue

            secure_storage.save_token_secret(
                account_name=token_data["account_name"],
                issuer_name=token_data["issuer_name"],
                secret_key=token_data["secret_key"],
                recovery_codes=token_data.get("recovery_codes") or "",
                digits=token_data.get("digits", otp.DEFAULT_DIGITS),
                period=token_data.get("period", otp.DEFAULT_PERIOD),
                algorithm=token_data.get("algorithm", otp.DEFAULT_ALGORITHM),
            )
            existing_tokens.add(fingerprint)
            restored_count += 1
        except secure_storage.LockedError:
            raise
        except Exception as e:
            print(f"Failed to restore a token: {e}")
            failed_count += 1
    return restored_count, skipped_count, failed_count
