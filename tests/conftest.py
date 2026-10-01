import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from core import app_lock, secure_storage

WINDOWS_MAX_VALUE_CHARS = 1280

class FakeKeyring(KeyringBackend):
    """In-memory keyring with the same value size limit as Windows Credential Manager."""
    priority = 1

    def __init__(self):
        super().__init__()
        self.store = {}
        self.fail_reads = False

    def get_password(self, service, username):
        if self.fail_reads:
            raise RuntimeError("simulated read failure")
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        if len(password) > WINDOWS_MAX_VALUE_CHARS:
            raise OSError(1783, "CredWrite", "The stub received bad data")
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.store:
            raise PasswordDeleteError()
        del self.store[(service, username)]

    def entries(self, service):
        return {username: value for (s, username), value in self.store.items() if s == service}

@pytest.fixture(autouse=True)
def fake_keyring(monkeypatch):
    previous = keyring.get_keyring()
    backend = FakeKeyring()
    keyring.set_keyring(backend)
    # Real scrypt settings take about a second per unlock; the tests don't need that
    monkeypatch.setattr(app_lock, "SCRYPT_N", 2 ** 10)
    yield backend
    secure_storage.clear_data_key()
    keyring.set_keyring(previous)

@pytest.fixture
def unlocked(fake_keyring):
    """Sets up a vault with the password 'correct horse' and unlocks storage."""
    data_key = app_lock.create_vault(app_lock.KIND_PASSWORD, "correct horse")
    secure_storage.set_data_key(data_key)
    return data_key
