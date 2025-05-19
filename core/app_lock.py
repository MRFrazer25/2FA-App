import hashlib
import keyring
import os

SERVICE_NAME = "Python2FAApp_Lock"
PIN_HASH_KEY = "app_pin_hash"
SALT_KEY = "app_pin_salt"
PBKDF2_ITERATIONS = 100000

# PIN Hashing and Verification 

def _generate_salt():
    """Generates a new random salt."""
    return os.urandom(16)

def _hash_pin(pin: str, salt: bytes) -> bytes:
    """Hashes the PIN using PBKDF2-SHA256."""
    return hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), salt, PBKDF2_ITERATIONS)

def set_app_pin(pin: str):
    """Hashes and stores the application PIN and its salt securely."""
    if len(pin) < 4:
        raise ValueError("PIN must be at least 4 digits long.")
    try:
        salt = _generate_salt()
        hashed_pin = _hash_pin(pin, salt)
        
        keyring.set_password(SERVICE_NAME, SALT_KEY, salt.hex()) # Store salt as hex
        keyring.set_password(SERVICE_NAME, PIN_HASH_KEY, hashed_pin.hex()) # Store hash as hex
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Cannot set application PIN.")
        raise
    except Exception as e:
        print(f"Error setting PIN: {e}")
        raise

def verify_app_pin(pin: str) -> bool:
    """Verifies the provided PIN against the stored hash."""
    try:
        salt_hex = keyring.get_password(SERVICE_NAME, SALT_KEY)
        stored_hash_hex = keyring.get_password(SERVICE_NAME, PIN_HASH_KEY)

        if not salt_hex or not stored_hash_hex:
            return False # PIN not set

        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
        
        hashed_attempt = _hash_pin(pin, salt)
        
        # Use direct equality for fixed-length hash comparison
        return hashed_attempt == stored_hash
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Cannot verify PIN.")
        return False # Or raise an error to indicate a critical issue
    except Exception as e:
        print(f"Error verifying PIN: {e}")
        return False

def is_pin_set() -> bool:
    """Checks if an application PIN has been set."""
    try:
        salt = keyring.get_password(SERVICE_NAME, SALT_KEY)
        pin_hash = keyring.get_password(SERVICE_NAME, PIN_HASH_KEY)
        return salt is not None and pin_hash is not None
    except keyring.errors.NoKeyringError:
        return False # If keyring is unavailable, or can't determine if PIN is set
    except Exception as e:
        print(f"Error checking if PIN is set: {e}")
        return False