import json
import pytest
from core import secure_storage as ss

SECRET = "JBSWY3DPEHPK3PXP"

def save(account="alice@example.com", issuer="GitHub", **kwargs):
    return ss.save_token_secret(account, issuer, SECRET, **kwargs)

def test_save_and_read_back(unlocked):
    identifier = save(recovery_codes="code-1\ncode-2", digits=8, period=60, algorithm="SHA256")
    token = ss.get_token_secret(identifier)
    assert token["account_name"] == "alice@example.com"
    assert token["issuer_name"] == "GitHub"
    assert token["secret_key"] == SECRET
    assert token["recovery_codes"] == "code-1\ncode-2"
    assert (token["digits"], token["period"], token["algorithm"]) == (8, 60, "SHA256")

def test_secrets_and_names_are_encrypted_at_rest(unlocked, fake_keyring):
    identifier = save(recovery_codes="my-recovery-code")
    stored = "".join(fake_keyring.entries(ss.SERVICE_NAME).values())
    for plaintext in (SECRET, "my-recovery-code", "alice@example.com", "GitHub"):
        assert plaintext not in stored
    assert "alice" not in identifier and "github" not in identifier.lower()

def test_locked_storage_refuses_access(unlocked):
    identifier = save()
    ss.clear_data_keys()
    with pytest.raises(ss.LockedError):
        ss.get_token_secret(identifier)
    with pytest.raises(ss.LockedError):
        save()

def test_wrong_key_cannot_decrypt(unlocked):
    identifier = save()
    ss.set_data_keys(ss.DataKeys({unlocked.current_id: b"\x00" * 32}, unlocked.current_id))
    assert ss.get_token_secret(identifier) is None

def test_encrypted_entries_cannot_be_swapped(unlocked, fake_keyring):
    first = save(account="first")
    second = save(account="second")
    entries = fake_keyring.store
    entries[(ss.SERVICE_NAME, first)], entries[(ss.SERVICE_NAME, second)] = \
        entries[(ss.SERVICE_NAME, second)], entries[(ss.SERVICE_NAME, first)]
    assert ss.get_token_secret(first) is None
    assert ss.get_token_secret(second) is None

def test_many_tokens_beyond_windows_size_limit(unlocked):
    identifiers = [save(account=f"someone.with.a.long.name{i}@example.com", issuer="Some Long Issuer Name") for i in range(150)]
    assert ss.get_all_token_identifiers() == identifiers
    assert len(ss.get_all_token_data()) == 150
    assert ss._stored_chunk_count(ss.ACCOUNTS_LIST_KEY) > 1

def test_large_recovery_codes_are_chunked_and_cleaned_up(unlocked, fake_keyring):
    big = "\n".join(f"code-{i:04d}-abcdefghij" for i in range(200))
    identifier = save(recovery_codes=big)
    assert ss.get_token_secret(identifier)["recovery_codes"] == big
    assert ss._stored_chunk_count(identifier) > 1

    save(identifier=identifier, recovery_codes="small")
    assert ss.get_token_secret(identifier)["recovery_codes"] == "small"
    assert not any(key.startswith(identifier + "#") for key in fake_keyring.entries(ss.SERVICE_NAME))

def test_delete_removes_entry_chunks_and_list_item(unlocked, fake_keyring):
    identifier = save(recovery_codes="x" * 3000)
    ss.delete_token_secret(identifier)
    assert ss.get_all_token_identifiers() == []
    assert not any(key.startswith(identifier) for key in fake_keyring.entries(ss.SERVICE_NAME))

def test_shrinking_list_removes_stale_chunks(unlocked, fake_keyring):
    identifiers = [save(account=f"user{i}") for i in range(60)]
    for identifier in identifiers:
        ss.delete_token_secret(identifier)
    assert not any(key.startswith(ss.ACCOUNTS_LIST_KEY + "#") for key in fake_keyring.entries(ss.SERVICE_NAME))

def test_read_failure_does_not_wipe_token_list(unlocked, fake_keyring):
    identifier = save()
    fake_keyring.fail_reads = True
    with pytest.raises(RuntimeError):
        save(account="bob")
    fake_keyring.fail_reads = False
    assert ss.get_all_token_identifiers() == [identifier]

def test_failed_list_write_rolls_back_new_token(unlocked, fake_keyring, monkeypatch):
    real_set = fake_keyring.set_password
    def failing_set(service, username, password):
        if username.startswith(ss.ACCOUNTS_LIST_KEY):
            raise OSError("simulated list write failure")
        real_set(service, username, password)
    monkeypatch.setattr(fake_keyring, "set_password", failing_set)
    with pytest.raises(OSError):
        save()
    assert fake_keyring.entries(ss.SERVICE_NAME) == {}

@pytest.mark.parametrize("secret", ["JBSWY3DPEHPK3PXP", "jbsw y3dp ehpk 3pxp", "A" * 26, "A" * 32 + "======"])
def test_valid_secrets(secret):
    assert ss.normalize_secret_key(secret) == secret.replace(" ", "").upper().rstrip("=")

@pytest.mark.parametrize("secret", ["SHORT", "JBSWY3DPEHPK3PX1", "A" * 17, "A" * 19])
def test_invalid_secrets(secret):
    with pytest.raises(ValueError):
        ss.normalize_secret_key(secret)

def test_invalid_code_settings_rejected(unlocked):
    with pytest.raises(ValueError):
        save(digits=5)
    with pytest.raises(ValueError):
        save(algorithm="MD5")

def write_legacy_token(fake_keyring, identifier, **overrides):
    data = {"account_name": "legacy@example.com", "issuer_name": "Legacy", "secret_key": SECRET + "====",
            "type": "TOTP", "recovery_codes": "old-code"}
    data.update(overrides)
    fake_keyring.store[(ss.SERVICE_NAME, identifier)] = json.dumps(data)

def test_migration_encrypts_plaintext_tokens(unlocked, fake_keyring):
    write_legacy_token(fake_keyring, "legacy_legacy@example.com")
    fake_keyring.store[(ss.SERVICE_NAME, ss.ACCOUNTS_LIST_KEY)] = json.dumps(["legacy_legacy@example.com"])
    encrypted_id = save()

    assert ss.reencrypt_outdated_tokens() == 1

    identifiers = ss.get_all_token_identifiers()
    assert len(identifiers) == 2 and identifiers[1] == encrypted_id
    token = ss.get_token_secret(identifiers[0])
    assert (token["account_name"], token["recovery_codes"], token["digits"]) == ("legacy@example.com", "old-code", 6)
    stored = "".join(fake_keyring.entries(ss.SERVICE_NAME).values())
    assert "old-code" not in stored and "legacy_legacy@example.com" not in fake_keyring.entries(ss.SERVICE_NAME)
    assert ss.reencrypt_outdated_tokens() == 0

def test_interrupted_migration_loses_nothing(unlocked, fake_keyring, monkeypatch):
    write_legacy_token(fake_keyring, "legacy_one")
    fake_keyring.store[(ss.SERVICE_NAME, ss.ACCOUNTS_LIST_KEY)] = json.dumps(["legacy_one"])
    real_set = fake_keyring.set_password
    def failing_set(service, username, password):
        if username == ss.ACCOUNTS_LIST_KEY:
            raise OSError("simulated crash")
        real_set(service, username, password)
    monkeypatch.setattr(fake_keyring, "set_password", failing_set)
    with pytest.raises(OSError):
        ss.reencrypt_outdated_tokens()

    monkeypatch.setattr(fake_keyring, "set_password", real_set)
    assert ss.get_all_token_identifiers() == ["legacy_one"]
    assert ss.get_token_secret("legacy_one")["account_name"] == "legacy@example.com"
    assert ss.reencrypt_outdated_tokens() == 1
    assert len(ss.get_all_token_data()) == 1
