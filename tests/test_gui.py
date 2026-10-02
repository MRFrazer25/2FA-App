"""Smoke tests for the windows and unlock flow. Dialog results are stubbed, so nothing waits for input."""
import tkinter as tk
import pytest
from core import app_lock, secure_storage as ss
from tests.test_app_lock import write_legacy_pin
from tests.test_secure_storage import write_legacy_token

try:
    tk.Tk().destroy()
except tk.TclError:
    pytest.skip("No display available for GUI tests", allow_module_level=True)

import main
from ui.add_token_dialog import AddTokenDialog
from ui.passcode_dialog import UnlockDialog, SetPasscodeDialog
from ui.recovery_codes_dialog import RecoveryCodesDialog

SECRET = "JBSWY3DPEHPK3PXP"

def stub_dialog(monkeypatch, dialog_class, result):
    """Makes dialog_class.get_result() close the dialog and return result (or call result(dialog))."""
    def get_result(self):
        value = result(self) if callable(result) else result
        self.destroy()
        return value
    monkeypatch.setattr(dialog_class, "get_result", get_result)

def stub_unlock_with(passcode):
    """Unlock dialog stub that checks the passcode with the dialog's real verify function."""
    return lambda dialog: dialog._verify(passcode)

@pytest.fixture
def no_message_boxes(monkeypatch):
    shown = []
    for name in ("showinfo", "showerror"):
        monkeypatch.setattr(main.messagebox, name, lambda title, message, **kwargs: shown.append((title, message)))
    return shown

@pytest.fixture
def app(monkeypatch, no_message_boxes):
    """An unlocked app (password 'correct horse') with two tokens."""
    stub_dialog(monkeypatch, SetPasscodeDialog, ("password", "correct horse"))
    application = main.TwoFactorApp()
    ss.save_token_secret("alice@example.com", "GitHub", SECRET, recovery_codes="code-1")
    ss.save_token_secret("bob@example.com", "Google", "GEZDGNBVGY3TQOJQGEZDGNBVGY", digits=8, period=60, algorithm="SHA256")
    application.load_and_display_tokens()
    yield application
    try:
        application._on_closing()
    except tk.TclError:
        pass # The test already closed the app

def search(application, text):
    application.search_entry.delete(0, "end")
    if text:
        application.search_entry.insert(0, text)
    application._filter_tokens_by_search()

def visible_issuers(application):
    return [card.issuer_name for card in application.token_cards.values() if card.winfo_manager() == "pack"]

def test_first_launch_creates_encrypted_vault(app):
    assert app.app_unlocked
    assert app_lock.passcode_kind() == "password"
    assert app_lock.unlock("correct horse") is not None

def test_cards_use_code_settings(app):
    google = next(card for card in app.token_cards.values() if card.issuer_name == "Google")
    assert google.totp.digits == 8 and google.totp.interval == 60
    assert len(google.token_label.cget("text").replace(" ", "")) == 8

def test_search_filters_loaded_cards(app):
    search(app, "goog")
    assert visible_issuers(app) == ["Google"]
    search(app, "nomatch")
    assert not app.token_scrollable_frame._parent_frame.winfo_manager()
    assert "nomatch" in app.no_tokens_label.cget("text")
    search(app, "")
    assert visible_issuers(app) == ["GitHub", "Google"]

def test_lock_closes_dialogs_and_drops_secrets(app, monkeypatch):
    edit_dialog = AddTokenDialog(master=app, existing_data=ss.get_all_token_data()[0])
    card = next(iter(app.token_cards.values()))
    codes_dialog = RecoveryCodesDialog(card.master, title="Codes", recovery_codes="code-1")
    seen_while_locked = {}
    def unlock_while_checking_state(dialog):
        seen_while_locked.update(dialogs_open=edit_dialog.winfo_exists() or codes_dialog.winfo_exists(),
                                 cards=len(app.token_cards), data_keys=ss._data_keys)
        return dialog._verify("correct horse")
    stub_dialog(monkeypatch, UnlockDialog, unlock_while_checking_state)

    app.lock_application()

    assert seen_while_locked == {"dialogs_open": False, "cards": 0, "data_keys": None}
    assert app.app_unlocked and len(app.token_cards) == 2

def test_reload_cancels_card_timers(app):
    old_cards = list(app.token_cards.values())
    jobs = [card._update_job for card in old_cards]
    app.load_and_display_tokens()
    pending = app.tk.call("after", "info")
    assert all(not card.winfo_exists() for card in old_cards)
    assert not any(job in pending for job in jobs)

def test_empty_state(app):
    for identifier in list(app.token_cards):
        ss.delete_token_secret(identifier)
    app.load_and_display_tokens()
    assert app.no_tokens_label.cget("text") == main.NO_TOKENS_TEXT
    assert not app.search_entry.winfo_manager()

def test_unlock_dialog_counts_attempts_and_locks_out(no_message_boxes):
    app_lock.create_vault("pin", "123456")
    root = tk.Tk()
    root.withdraw()
    try:
        dialog = UnlockDialog(root, verify=app_lock.unlock, kind="pin")
        dialog.passcode_entry.insert(0, "000000")
        dialog._ok_event()
        assert "2 more attempt(s)" in dialog.error_label_text.get()
        for _ in range(2):
            dialog.passcode_entry.insert(0, "000000")
            dialog._ok_event()
        assert "Try again in 30 seconds" in dialog.error_label_text.get()
        assert dialog.ok_button.cget("state") == "disabled"
        dialog.passcode_entry.insert(0, "123456")
        dialog._ok_event() # Enter during a lockout is ignored too
        assert dialog.winfo_exists() and dialog._result is None
        dialog.destroy()

        # A new window (as after restarting the app) is still locked out
        dialog = UnlockDialog(root, verify=app_lock.unlock, kind="pin")
        assert "Try again in" in dialog.error_label_text.get()
        assert dialog.ok_button.cget("state") == "disabled"
        dialog.destroy()
    finally:
        root.destroy()

def test_unlock_dialog_survives_verify_errors(no_message_boxes):
    root = tk.Tk()
    root.withdraw()
    try:
        def failing_verify(passcode):
            raise RuntimeError("keyring unavailable")
        dialog = UnlockDialog(root, verify=failing_verify, kind="pin")
        dialog.passcode_entry.insert(0, "123456")
        dialog._ok_event()
        assert "keyring unavailable" in dialog.error_label_text.get()
        assert dialog.ok_button.cget("state") == "normal" and dialog.winfo_exists()
        dialog.destroy()
    finally:
        root.destroy()

def test_entries_stay_masked_after_switching_and_mismatch(no_message_boxes):
    """CTkEntry drops its masking if an entry already showing its placeholder is cleared again.
    Focus changes are simulated so this doesn't depend on window focus."""
    root = tk.Tk()
    root.withdraw()
    try:
        dialog = SetPasscodeDialog(root)
        entries = (dialog.passcode_entry, dialog.confirm_entry)
        for entry in entries:
            entry._entry_focus_out() # e.g. the user switched to another window; placeholder shows
        dialog.kind_selector.set("PIN")
        dialog._on_kind_change("PIN")
        dialog.passcode_entry._entry_focus_in()
        dialog.passcode_entry.insert(0, "123456")
        dialog._ok_event() # Confirm left empty: a mismatch, which clears the confirm entry
        for entry in entries:
            entry._entry_focus_in()
            assert entry._entry.cget("show") == "*"
        assert dialog.passcode_entry.get() == "123456"
        dialog.destroy()
    finally:
        root.destroy()

def test_set_passcode_dialog_validation(no_message_boxes):
    root = tk.Tk()
    root.withdraw()
    try:
        dialog = SetPasscodeDialog(root)
        dialog.kind_selector.set("PIN")
        dialog._on_kind_change("PIN")
        dialog.passcode_entry.insert(0, "1234")
        dialog.confirm_entry.insert(0, "1234")
        dialog._ok_event()
        assert "at least 6 digits" in dialog.error_label_text.get()
        dialog.passcode_entry.delete(0, "end")
        dialog.passcode_entry.insert(0, "123456")
        dialog.confirm_entry.delete(0, "end")
        dialog.confirm_entry.insert(0, "123456")
        dialog._ok_event()
        assert dialog._result == ("pin", "123456")
    finally:
        root.destroy()

def test_add_dialog_fills_from_otpauth_link(app):
    dialog = AddTokenDialog(master=app)
    dialog.secret_entry.insert(0, "otpauth://totp/GitHub:carol?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA512&issuer=GitHub")
    dialog._check_for_otpauth_link()
    assert (dialog.issuer_entry.get(), dialog.account_entry.get(), dialog.secret_entry.get()) == ("GitHub", "carol", SECRET)
    assert dialog._get_code_options() == (8, 60, "SHA512")
    dialog._ok_event()
    assert dialog._user_input["algorithm"] == "SHA512" and not dialog.winfo_exists()

@pytest.mark.parametrize("legacy_pin, expected_kind", [("123456", "pin"), ("1234", "password")])
def test_legacy_pin_upgrade(fake_keyring, monkeypatch, no_message_boxes, legacy_pin, expected_kind):
    write_legacy_pin(fake_keyring, legacy_pin)
    write_legacy_token(fake_keyring, "legacy_token")
    fake_keyring.store[(ss.SERVICE_NAME, ss.ACCOUNTS_LIST_KEY)] = '["legacy_token"]'
    stub_dialog(monkeypatch, UnlockDialog, stub_unlock_with(legacy_pin))
    # Only shown when the old PIN is too short to keep
    stub_dialog(monkeypatch, SetPasscodeDialog, ("password", "a stronger password"))

    application = main.TwoFactorApp()
    try:
        assert application.app_unlocked
        assert not app_lock.has_legacy_pin()
        assert app_lock.passcode_kind() == expected_kind
        assert app_lock.unlock(legacy_pin if expected_kind == "pin" else "a stronger password") is not None
        [token] = ss.get_all_token_data()
        assert token["account_name"] == "legacy@example.com"
        assert "legacy_token" not in fake_keyring.entries(ss.SERVICE_NAME)
        assert no_message_boxes[-1][0] == "Tokens Encrypted"
    finally:
        application._on_closing()

def test_startup_unlock_with_existing_vault(fake_keyring, monkeypatch, no_message_boxes):
    data_keys = app_lock.create_vault("pin", "246810")
    ss.set_data_keys(data_keys)
    ss.save_token_secret("alice", "GitHub", SECRET)
    ss.clear_data_keys()
    stub_dialog(monkeypatch, UnlockDialog, stub_unlock_with("246810"))

    application = main.TwoFactorApp()
    try:
        assert application.app_unlocked and ss._data_keys == data_keys
    finally:
        application._on_closing()

def test_lock_screen_error_exits_instead_of_hiding_forever(app, monkeypatch):
    def broken_kind():
        raise RuntimeError("keyring unavailable")
    monkeypatch.setattr(app_lock, "passcode_kind", broken_kind)
    with pytest.raises(SystemExit):
        app.lock_application()

def test_migration_error_does_not_block_unlock(app, monkeypatch):
    def broken_migration():
        raise RuntimeError("simulated migration failure")
    monkeypatch.setattr(ss, "reencrypt_outdated_tokens", broken_migration)
    stub_dialog(monkeypatch, UnlockDialog, stub_unlock_with("correct horse"))
    app.lock_application()
    assert app.app_unlocked and len(app.token_cards) == 2

def test_password_dialog_enter_is_bound_once(no_message_boxes):
    """Enter is handled by the dialog's own binding; a second binding on the fields would submit twice."""
    from ui.password_dialog import PasswordDialog
    root = tk.Tk()
    root.withdraw()
    try:
        dialog = PasswordDialog(root)
        assert dialog.bind("<Return>")
        for entry in (dialog.password_entry, dialog.confirm_password_entry):
            assert not entry._entry.bind("<Return>")
        dialog.destroy()
    finally:
        root.destroy()

def test_dialogs_center_on_screen_when_main_window_is_hidden(no_message_boxes):
    """At startup and on the lock screen the main window is hidden, so dialogs center on the screen."""
    from ui.password_dialog import PasswordDialog
    root = tk.Tk()
    root.withdraw()
    try:
        for dialog in (SetPasscodeDialog(root), UnlockDialog(root, verify=lambda p: None),
                       PasswordDialog(root), RecoveryCodesDialog(root, title="Codes", recovery_codes="x")):
            dialog.update()
            dialog._center_window() # Raised AttributeError before the fix
            dialog.destroy()
    finally:
        root.destroy()

def test_switching_between_home_and_settings(app):
    from ui.settings_frame import SettingsFrame
    app._show_frame_callback("Settings")
    settings = app.frames[SettingsFrame]
    assert settings.winfo_manager() == "grid" and not app.home_frame_container.winfo_manager()
    app._show_frame_callback("Home")
    assert not settings.winfo_manager() and app.home_frame_container.winfo_manager() == "grid"
    assert len(app.token_cards) == 2

def test_unlocking_from_settings_hides_settings(app, monkeypatch):
    """After unlocking, the window isn't drawn yet; Settings must still be hidden behind Home."""
    from ui.settings_frame import SettingsFrame
    app._show_frame_callback("Settings")
    stub_dialog(monkeypatch, UnlockDialog, stub_unlock_with("correct horse"))
    app.lock_application()
    assert not app.frames[SettingsFrame].winfo_manager()
    assert app.home_frame_container.winfo_manager() == "grid"

def test_change_pin_from_settings_reloads_tokens(app, monkeypatch):
    from ui.settings_frame import SettingsFrame
    old_identifiers = set(app.token_cards)
    stub_dialog(monkeypatch, UnlockDialog, stub_unlock_with("correct horse"))
    stub_dialog(monkeypatch, SetPasscodeDialog, ("pin", "135790"))
    app._show_frame_callback("Settings")

    app.frames[SettingsFrame]._handle_change_pin()

    assert app_lock.passcode_kind() == "pin" and app_lock.unlock("135790")
    # Tokens moved to new identifiers, and the cards point at them
    assert set(app.token_cards) == {token["identifier"] for token in ss.get_all_token_data()}
    assert not set(app.token_cards) & old_identifiers
    assert len(app.token_cards) == 2
