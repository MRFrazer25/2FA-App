import hashlib
import json
import os
import pytest
from core import app_lock, secure_storage as ss
from tests.test_secure_storage import write_legacy_token

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
    data_keys = app_lock.create_vault("pin", "246810")
    assert app_lock.has_vault()
    assert app_lock.passcode_kind() == "pin"
    assert app_lock.unlock("246810") == data_keys
    assert app_lock.unlock("246811") is None

def test_vault_record_has_no_plaintext_key(fake_keyring):
    data_keys = app_lock.create_vault("password", "correct horse")
    record = json.loads(fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)])
    assert data_keys.current_key.hex() not in json.dumps(record)
    assert record["kdf"] == "scrypt"

def unlock_and_save_token(passcode, account="alice"):
    data_keys = app_lock.unlock(passcode)
    ss.set_data_keys(data_keys)
    return data_keys, ss.save_token_secret(account, "GitHub", "JBSWY3DPEHPK3PXP")

def test_save_refused_after_stale_keys_left_from_passcode_change(fake_keyring):
    app_lock.create_vault("pin", "246810")
    old_keys, _ = unlock_and_save_token("246810")
    new_keys = app_lock.change_passcode(old_keys, "pin", "135790")
    ss.set_data_keys(old_keys)
    with pytest.raises(ss.LockedError, match="changed"):
        ss.save_token_secret("bob", "GitHub", "JBSWY3DPEHPK3PXP")
    ss.set_data_keys(new_keys)
    [token] = ss.get_all_token_data()
    assert token["account_name"] == "alice"
    assert json.loads(fake_keyring.store[(ss.SERVICE_NAME, token["identifier"])])["kid"] == new_keys.current_id

def test_create_vault_encrypts_legacy_tokens_and_records_migrated(fake_keyring):
    write_legacy_token(fake_keyring, "legacy_one")
    fake_keyring.store[(ss.SERVICE_NAME, ss.ACCOUNTS_LIST_KEY)] = json.dumps(["legacy_one"])
    keys = app_lock.create_vault("pin", "246810")
    assert keys.migrated is True
    record = json.loads(fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)])
    assert record["migrated"] is True
    assert app_lock.current_key_id() == keys.current_id
    [token] = ss.get_all_token_data()
    assert token["account_name"] == "legacy@example.com"
    assert "legacy_one" not in fake_keyring.entries(ss.SERVICE_NAME)

def test_failed_plaintext_migration_retries_on_unlock(fake_keyring, monkeypatch):
    write_legacy_token(fake_keyring, "legacy_one")
    fake_keyring.store[(ss.SERVICE_NAME, ss.ACCOUNTS_LIST_KEY)] = json.dumps(["legacy_one"])
    real_reencrypt = ss.reencrypt_outdated_tokens
    monkeypatch.setattr(ss, "reencrypt_outdated_tokens", lambda: (_ for _ in ()).throw(OSError("simulated crash")))
    keys = app_lock.create_vault("pin", "246810")
    assert keys.migrated is False
    assert ss.get_token_secret("legacy_one")["account_name"] == "legacy@example.com"
    monkeypatch.setattr(ss, "reencrypt_outdated_tokens", real_reencrypt)
    finished = app_lock.unlock("246810")
    assert finished.migrated is True
    [token] = ss.get_all_token_data()
    assert token["account_name"] == "legacy@example.com"
    assert "legacy_one" not in fake_keyring.entries(ss.SERVICE_NAME)

def test_migrated_flag_cannot_be_cleared_without_passcode(fake_keyring):
    app_lock.create_vault("pin", "246810")
    record = json.loads(fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)])
    record["migrated"] = False
    fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)] = json.dumps(record)
    assert app_lock.unlock("246810") is None

def test_changing_passcode_replaces_data_key(fake_keyring):
    app_lock.create_vault("pin", "246810")
    old_keys, _ = unlock_and_save_token("246810")
    old_vault_copy = fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)]

    new_keys = app_lock.change_passcode(old_keys, "password", "a much longer password")

    assert app_lock.passcode_kind() == "password"
    assert app_lock.unlock("246810") is None
    assert app_lock.unlock("a much longer password") == new_keys
    assert new_keys.current_key != old_keys.current_key
    assert ss._data_keys == new_keys
    [token] = ss.get_all_token_data()
    assert token["account_name"] == "alice"
    stored = json.loads(fake_keyring.store[(ss.SERVICE_NAME, token["identifier"])])
    assert stored["kid"] == new_keys.current_id
    assert len(json.loads(fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)])["keys"]) == 1

    # An old copy of the vault plus the old PIN can't read tokens saved after the change
    fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)] = old_vault_copy
    ss.set_data_keys(app_lock.unlock("246810"))
    assert ss.get_token_secret(token["identifier"]) is None

def test_interrupted_passcode_change_finishes_on_next_unlock(fake_keyring, monkeypatch):
    app_lock.create_vault("pin", "246810")
    old_keys, _ = unlock_and_save_token("246810")
    real_reencrypt = ss.reencrypt_outdated_tokens
    def crash():
        raise OSError("simulated crash while moving tokens")
    monkeypatch.setattr(ss, "reencrypt_outdated_tokens", crash)

    staged = app_lock.change_passcode(old_keys, "pin", "135790")

    # The new PIN already works, both keys are kept, and the token is still readable
    assert len(staged.keys) == 2
    assert app_lock.unlock("246810") is None
    assert ss.get_all_token_data()[0]["account_name"] == "alice"

    monkeypatch.setattr(ss, "reencrypt_outdated_tokens", real_reencrypt)
    assert staged.migrated is True
    finished = app_lock.unlock("135790")
    assert len(finished.keys) == 1 and finished.current_id == staged.current_id
    assert len(json.loads(fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.VAULT_KEY)])["keys"]) == 1
    [token] = ss.get_all_token_data()
    assert json.loads(fake_keyring.store[(ss.SERVICE_NAME, token["identifier"])])["kid"] == finished.current_id

class FakeClock:
    def __init__(self, monkeypatch):
        self.now = 1_000_000.0
        monkeypatch.setattr(app_lock.time, "time", lambda: self.now)

def test_lockout_starts_after_three_wrong_attempts_and_doubles(monkeypatch):
    clock = FakeClock(monkeypatch)
    app_lock.create_vault("pin", "246810")
    assert app_lock.attempts_before_lockout() == 3
    for expected_left in (2, 1):
        assert app_lock.unlock("000000") is None
        assert app_lock.attempts_before_lockout() == expected_left
        assert app_lock.seconds_locked_out() == 0

    assert app_lock.unlock("000000") is None
    assert app_lock.seconds_locked_out() == 30
    with pytest.raises(app_lock.LockedOutError):
        app_lock.unlock("246810") # Even the right PIN waits

    clock.now += 30
    assert app_lock.unlock("000000") is None
    assert app_lock.seconds_locked_out() == 60

def test_lockout_is_capped_and_survives_restart(monkeypatch, fake_keyring):
    clock = FakeClock(monkeypatch)
    app_lock.create_vault("pin", "246810")
    for _ in range(20):
        clock.now += app_lock.MAX_LOCKOUT_SECONDS
        assert app_lock.unlock("000000") is None
    assert app_lock.seconds_locked_out() == app_lock.MAX_LOCKOUT_SECONDS
    # Stored in the keyring, so nothing in memory needs to survive; moving the clock back can't extend it
    assert app_lock.LOCKOUT_KEY in fake_keyring.entries(app_lock.SERVICE_NAME)
    clock.now -= 10 ** 6
    assert app_lock.seconds_locked_out() == app_lock.MAX_LOCKOUT_SECONDS

def test_correct_passcode_resets_failures(monkeypatch, fake_keyring):
    FakeClock(monkeypatch)
    app_lock.create_vault("pin", "246810")
    app_lock.unlock("000000")
    app_lock.unlock("000000")
    assert app_lock.unlock("246810") is not None
    assert app_lock.attempts_before_lockout() == 3
    assert app_lock.LOCKOUT_KEY not in fake_keyring.entries(app_lock.SERVICE_NAME)

def test_unreadable_lockout_entry_is_ignored(fake_keyring):
    fake_keyring.store[(app_lock.SERVICE_NAME, app_lock.LOCKOUT_KEY)] = "not json"
    assert app_lock.seconds_locked_out() == 0
    assert app_lock.attempts_before_lockout() == 3

def test_legacy_pin_uses_the_same_lockout(monkeypatch, fake_keyring):
    FakeClock(monkeypatch)
    write_legacy_pin(fake_keyring, "1234")
    for _ in range(3):
        assert not app_lock.verify_legacy_pin("9999")
    with pytest.raises(app_lock.LockedOutError):
        app_lock.verify_legacy_pin("1234")

@pytest.mark.parametrize("seconds, text", [(1, "1 second"), (30, "30 seconds"), (60, "1 min 00 s"), (900, "15 min 00 s")])
def test_format_wait(seconds, text):
    assert app_lock.format_wait(seconds) == text

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
