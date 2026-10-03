import base64
import json
import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core import backup, secure_storage as ss

SECRET = "JBSWY3DPEHPK3PXP"
TOKEN = {"account_name": "alice@example.com", "issuer_name": "GitHub", "secret_key": SECRET,
         "recovery_codes": "code-1", "digits": 8, "period": 60, "algorithm": "SHA256"}

def test_round_trip():
    content = backup.encrypt_backup([dict(TOKEN, identifier="abc")], "backup password")
    assert SECRET not in json.dumps(content)
    assert backup.decrypt_backup(content, "backup password") == [TOKEN]

def test_wrong_password():
    content = backup.encrypt_backup([TOKEN], "backup password")
    with pytest.raises(backup.BackupPasswordError):
        backup.decrypt_backup(content, "wrong password")

def test_legacy_backup_without_iteration_count():
    tokens = [{"account_name": "a", "issuer_name": "b", "secret_key": SECRET, "type": "TOTP"}]
    salt, nonce = os.urandom(16), os.urandom(12)
    key = backup._derive_key("old password", salt, backup.LEGACY_PBKDF2_ITERATIONS)
    content = {
        "version": "1.0_encrypted",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(AESGCM(key).encrypt(nonce, json.dumps(tokens).encode(), None)).decode(),
    }
    assert backup.decrypt_backup(content, "old password") == tokens

@pytest.mark.parametrize("content", [
    [],
    {"version": "1.1_encrypted"},
    {"version": "1.1_encrypted", "salt": "", "nonce": "", "ciphertext": "", "kdf_iterations": 10 ** 9},
    {"version": "1.1_encrypted", "salt": "", "nonce": "", "ciphertext": "", "kdf_iterations": "600000"},
])
def test_invalid_backup_files(content):
    with pytest.raises(backup.BackupFormatError):
        backup.decrypt_backup(content, "password")

def test_restore_keeps_all_fields_and_skips_duplicates(unlocked):
    tokens = [TOKEN, dict(TOKEN, secret_key="jbsw y3dp ehpk 3pxp"), {"account_name": "missing secret", "issuer_name": "X"}]
    assert backup.restore_tokens(tokens) == (1, 1, 1)
    assert backup.restore_tokens(tokens) == (0, 2, 1)

    [restored] = ss.get_all_token_data()
    for field in backup.BACKUP_FIELDS:
        assert restored[field] == TOKEN[field]

def test_restore_rejects_non_string_fields_without_aborting(unlocked):
    valid = {"account_name": "carol@example.com", "issuer_name": "GitLab", "secret_key": SECRET}
    invalid = [
        {"account_name": ["not", "text"], "issuer_name": "X", "secret_key": SECRET},
        {"account_name": "a", "issuer_name": {"name": "X"}, "secret_key": SECRET},
        {"account_name": 123, "issuer_name": "X", "secret_key": SECRET},
        {"account_name": "a", "issuer_name": "X", "secret_key": SECRET, "recovery_codes": ["a"]},
    ]
    assert backup.restore_tokens([valid, *invalid]) == (1, 0, 4)
    [restored] = ss.get_all_token_data()
    assert restored["account_name"] == "carol@example.com"

def test_restore_old_backup_defaults_code_settings(unlocked):
    assert backup.restore_tokens([{"account_name": "a", "issuer_name": "b", "secret_key": SECRET, "type": "TOTP"}]) == (1, 0, 0)
    [restored] = ss.get_all_token_data()
    assert (restored["digits"], restored["period"], restored["algorithm"], restored["recovery_codes"]) == (6, 30, "SHA1", "")
