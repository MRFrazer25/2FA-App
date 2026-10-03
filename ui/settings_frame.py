import customtkinter as ctk
from core import app_lock, backup
from ui.passcode_dialog import UnlockDialog, SetPasscodeDialog
from ui.password_dialog import PasswordDialog # For backup password
import tkinter.messagebox as messagebox
from core.secure_storage import (
    LockedError,
    save_auto_lock_setting,
    get_auto_lock_setting,
    DEFAULT_AUTO_LOCK_SECONDS,
    get_all_token_data,
)
import json
import traceback

class SettingsFrame(ctk.CTkFrame):
    """Frame for managing application settings, including PIN/password, auto-lock, and backup/restore."""
    def __init__(self, master, app_instance):
        # app_instance is the main application window, used for dialogs and to refresh the token list
        super().__init__(master)
        self.master_app = app_instance

        self.grid_columnconfigure(0, weight=0) # Column for labels
        self.grid_columnconfigure(1, weight=1) # Column for buttons/options

        title_label = ctk.CTkLabel(self, text="Application Settings", font=ctk.CTkFont(size=20, weight="bold"))
        title_label.grid(row=0, column=0, columnspan=2, padx=20, pady=(20,30), sticky="w")

        # PIN/Password Management Section
        pin_management_label = ctk.CTkLabel(self, text="Security:", font=ctk.CTkFont(size=16, weight="bold"))
        pin_management_label.grid(row=1, column=0, padx=20, pady=(10,5), sticky="w")

        self.change_pin_button = ctk.CTkButton(self, text="Change PIN / Password", command=self._handle_change_pin, width=180)
        self.change_pin_button.grid(row=2, column=0, padx=20, pady=5, sticky="w")

        # Auto-Lock Setting
        auto_lock_heading_label = ctk.CTkLabel(self, text="Auto-Lock:", font=ctk.CTkFont(size=16, weight="bold"))
        auto_lock_heading_label.grid(row=4, column=0, padx=20, pady=(30,5), sticky="w")

        self.auto_lock_label = ctk.CTkLabel(self, text="Timeout:")
        self.auto_lock_label.grid(row=5, column=0, padx=20, pady=(10,5), sticky="w")

        self.auto_lock_options = {
            "Disabled": 0,
            "1 Minute": 60,
            "5 Minutes": 300,
            "15 Minutes": 900,
            "30 Minutes": 1800,
            "1 Hour": 3600
        }
        self.auto_lock_dropdown = ctk.CTkOptionMenu(self, values=list(self.auto_lock_options.keys()),
                                                      command=self._on_auto_lock_change, width=150)
        self.auto_lock_dropdown.grid(row=5, column=1, padx=20, pady=(10,5), sticky="w")
        self._load_and_set_auto_lock_display()

        # Backup & Restore Section
        backup_restore_label = ctk.CTkLabel(self, text="Data Management:", font=ctk.CTkFont(size=16, weight="bold"))
        backup_restore_label.grid(row=6, column=0, columnspan=2, padx=20, pady=(20,5), sticky="w")

        self.backup_tokens_button = ctk.CTkButton(self, text="Backup Tokens...", command=self._handle_backup_tokens, width=180)
        self.backup_tokens_button.grid(row=7, column=0, padx=20, pady=5, sticky="w")

        self.restore_tokens_button = ctk.CTkButton(self, text="Restore Tokens...", command=self._handle_restore_tokens, width=180)
        self.restore_tokens_button.grid(row=7, column=1, padx=20, pady=5, sticky="w")
        self.grid_rowconfigure(8, weight=1)

    def _load_and_set_auto_lock_display(self):
        current_timeout_seconds = get_auto_lock_setting()
        # Find the display string for the current timeout
        display_value = "5 Minutes" # Default display if not found, matching DEFAULT_AUTO_LOCK_SECONDS typically
        for text, seconds in self.auto_lock_options.items():
            if seconds == current_timeout_seconds:
                display_value = text
                break
        self.auto_lock_dropdown.set(display_value)

    def _on_auto_lock_change(self, selected_display_value: str):
        timeout_seconds = self.auto_lock_options.get(selected_display_value, DEFAULT_AUTO_LOCK_SECONDS)
        try:
            save_auto_lock_setting(timeout_seconds)
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Auto-Lock Error", f"Could not save the auto-lock setting: {e}", parent=self.master_app)
            self._load_and_set_auto_lock_display() # Show the setting that's still in effect
            return
        messagebox.showinfo("Auto-Lock Updated", f"Auto-lock timeout set to {selected_display_value}.", parent=self.master_app)

        # Notify the main app to update its timer
        self.master_app.update_auto_lock_and_reset_timer()

    def _handle_backup_tokens(self):
        backup_file_path = ctk.filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Encrypted JSON files", "*.json"), ("All files", "*.*")],
            title="Save Encrypted Tokens Backup",
            parent=self.master_app
        )

        if not backup_file_path:
            return

        try:
            all_tokens = get_all_token_data()
            if not all_tokens:
                messagebox.showinfo("Backup Tokens", "No tokens found to backup.", parent=self.master_app)
                return

            # Get password for encryption
            password_dialog = PasswordDialog(self.master_app, title="Set Backup Encryption Password")
            backup_password = password_dialog.get_password()

            if not backup_password:
                messagebox.showinfo("Backup Cancelled", "Backup password not provided. Backup cancelled.", parent=self.master_app)
                return

            backup_content = backup.encrypt_backup(all_tokens, backup_password)
            with open(backup_file_path, 'w', encoding='utf-8') as f:
                json.dump(backup_content, f, indent=4)

            messagebox.showinfo("Backup Successful", f"All tokens securely backed up to:\n{backup_file_path}", parent=self.master_app)

        except Exception as e:
            messagebox.showerror("Backup Error", f"An error occurred during encrypted backup: {e}", parent=self.master_app)
            traceback.print_exc()

    def _handle_restore_tokens(self):
        restore_file_path = ctk.filedialog.askopenfilename(
            filetypes=[("Encrypted JSON files", "*.json"), ("All files", "*.*")],
            title="Select Encrypted Backup File to Restore",
            parent=self.master_app
        )

        if not restore_file_path:
            return

        try:
            with open(restore_file_path, 'r', encoding='utf-8') as f:
                backup_content = json.load(f)
            backup.check_backup_format(backup_content)

            # Get password for decryption
            password_dialog = PasswordDialog(self.master_app, title="Backup Password",
                                             prompt="Enter the password for this backup file:", confirm=False)
            backup_password = password_dialog.get_password() # Returns None if cancelled

            if not backup_password:
                messagebox.showinfo("Restore Cancelled", "Password not provided. Restore cancelled.", parent=self.master_app)
                return

            tokens_to_restore = backup.decrypt_backup(backup_content, backup_password)
            if not tokens_to_restore:
                messagebox.showinfo("Restore Tokens", "No tokens found in the (decrypted) backup file.", parent=self.master_app)
                return

            confirm_restore = messagebox.askyesno(
                "Confirm Restore",
                f"Found {len(tokens_to_restore)} token(s) in the backup file.\n\n"
                "Restoring will add tokens from the backup. "
                "Tokens that are already in the app (same issuer, account, and secret key) will be skipped.\n\n"
                "Do you want to proceed with the restore?",
                parent=self.master_app
            )

            if not confirm_restore:
                return

            restored_count, skipped_count, failed_count = backup.restore_tokens(tokens_to_restore)
            summary_message = (f"Restore completed.\n\nSuccessfully restored: {restored_count} token(s)."
                               f"\nAlready in the app (skipped): {skipped_count} token(s)."
                               f"\nFailed to restore: {failed_count} token(s).")
            messagebox.showinfo("Restore Summary", summary_message, parent=self.master_app)

            self.master_app.load_and_display_tokens()

        except LockedError as e:
            self.master_app.require_unlock_again(e)
        except backup.BackupPasswordError as e:
            messagebox.showerror("Decryption Failed", str(e), parent=self.master_app)
        except backup.BackupFormatError as e:
            messagebox.showerror("Restore Error", str(e), parent=self.master_app)
        except json.JSONDecodeError:
            messagebox.showerror("Restore Error", "Invalid JSON file. Could not decode backup data (outer structure).", parent=self.master_app)
        except Exception as e:
            messagebox.showerror("Restore Error", f"An error occurred during restore: {e}", parent=self.master_app)
            traceback.print_exc()

    def _handle_change_pin(self):
        """Verifies the current PIN or password, then sets a new one and moves tokens to a new key."""
        current_kind = app_lock.passcode_kind()
        current_dialog = UnlockDialog(self.master_app, verify=app_lock.unlock, kind=current_kind,
                                      title="Verify Current PIN / Password",
                                      prompt=f"Enter your current {app_lock.describe(current_kind)} to change it:")
        data_keys = current_dialog.get_result()
        if not data_keys:
            return

        try:
            new_dialog = SetPasscodeDialog(self.master_app, title="Set New PIN / Password")
            result = new_dialog.get_result()
            if not result:
                return

            kind, passcode = result
            try:
                app_lock.change_passcode(data_keys, kind, passcode)
                messagebox.showinfo("Updated", f"Your {app_lock.describe(kind)} has been updated.", parent=self.master_app)
            except ValueError as ve:
                messagebox.showerror("Error", str(ve), parent=self.master_app)
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror("Error", f"Could not update your {app_lock.describe(kind)}: {e}", parent=self.master_app)
        finally:
            # Tokens move to new identifiers when the PIN changes, and verifying can also finish
            # an earlier interrupted change, so rebuild the cards whenever verification succeeded
            self.master_app.load_and_display_tokens()
