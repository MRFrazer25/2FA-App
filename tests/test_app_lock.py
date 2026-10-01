import hashlib
import json
import os
import pytest
from core import app_lock

def write_legacy_pin(fake_keyring, pin, new_format=False):
    salt = os.urandom(16)
    if new_format:
        pin_hash = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 600000)
        fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.LEGACY_PIN_HASH_KEY)] = f"pbkdf2_sha256$600000${salt.hex()}${pin_hash.hex()}"
    else:
        pin_hash = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 100000)
        fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.LEGACY_SALT_KEY)] = salt.hex()
        fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.LEGACY_PIN_HASH_KEY)] = pin_hash.hex()

@pytest.mark.parametrize("kind, passcode", [("pin", "123456"), ("pin", "0000000000"), ("password", "abcdefgh"), ("password", "12345678")])
def test_valid_passcodes(kind, passcode):
    app_lock.validate_passcode(kind, passcode)

@pytest.mark.parametrize("kind, passcode", [("pin", "12345"), ("pin", "12345a"), ("password", "short"), ("other", "whatever123")])
def test_invalid_passcodes(kind, passcode):
    with pytest.raises(ValueError):
        app_lock.validate_passcode(kind, passcode)

def test_unlock_with_correct_and_wrong_passcode():
    data_key = app_lock.create_vault("pin", "246810")
    assert app_lock.has_vault()
    assert app_lock.passcode_kind() == "pin"
    assert app_lock.unlock("246810") == data_key
    assert app_lock.unlock("246811") is None

def test_vault_record_has_no_plaintext_key(fake_keyring):
    data_key = app_lock.create_vault("password", "correct horse")
    record = json.loads(fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)])
    assert data_key.hex() not in json.dumps(record)
    assert record["kdf"] == "scrypt"

def test_changing_passcode_keeps_data_key():
    data_key = app_lock.create_vault("pin", "246810")
    app_lock.set_passcode(data_key, "password", "a much longer password")
    assert app_lock.passcode_kind() == "password"
    assert app_lock.unlock("246810") is None
    assert app_lock.unlock("a much longer password") == data_key

def test_has_vault_raises_on_keyring_error(fake_keyring):
    fake_keyring.fail_reads = True
    with pytest.raises(RuntimeError):
        app_lock.has_vault()

@pytest.mark.parametrize("new_format", [False, True])
def test_legacy_pin_verification(fake_keyring, new_format):
    write_legacy_pin(fake_keyring, "1234", new_format)
    assert not app_lock.has_vault()
    assert app_lock.has_legacy_pin()
    assert app_lock.verify_legacy_pin("1234")
    assert not app_lock.verify_legacy_pin("4321")

def test_creating_vault_removes_legacy_pin(fake_keyring):
    write_legacy_pin(fake_keyring, "123456")
    app_lock.create_vault("pin", "123456")
    assert not app_lock.has_legacy_pin()
    assert set(fake_keyring.entries(app_lock.SERVICE_NAME)) == {app_lock.VAULT_KEY}

@pytest.mark.parametrize("pin, kind", [("123456", "pin"), ("abcdefgh", "password"), ("1234", None), ("abc123", None)])
def test_legacy_pin_kind(pin, kind):
    assert app_lock.legacy_pin_kind(pin) == kind
