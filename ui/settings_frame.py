import customtkinter as ctk
from core import app_lock # For PIN operations
from ui.pin_dialog import PinDialog # For getting new PIN
from ui.password_dialog import PasswordDialog # For backup password
import tkinter.messagebox as messagebox
from core.secure_storage import save_auto_lock_setting, get_auto_lock_setting, DEFAULT_AUTO_LOCK_SECONDS, get_all_token_data, save_token_secret # Changed path
import json
import traceback
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64 # For encoding binary data to store in JSON

# Constants for encryption
PBKDF2_ITERATIONS = 390000
SALT_SIZE_BYTES = 16
AES_KEY_SIZE_BYTES = 32 # AES-256
AES_NONCE_SIZE_BYTES = 12 # Recommended for AES-GCM

class SettingsFrame(ctk.CTkFrame):
    """Frame for managing application settings, including PIN, auto-lock, and backup/restore."""
    def __init__(self, master, app_instance=None, **kwargs):
        # app_instance is a SettingsFrame-specific parameter to access the main application.
        # It must not be passed to the CTkFrame base class, which was causing an error.
        # The call to super().__init__(master) below ensures app_instance is handled by SettingsFrame only.
        super().__init__(master) # Pass only master, assuming no other CTkFrame args are needed from SettingsFrame's **kwargs
        self.master_app = app_instance if app_instance is not None else self.winfo_toplevel()

        self.grid_columnconfigure(0, weight=0) # Column for labels
        self.grid_columnconfigure(1, weight=1) # Column for buttons/options

        title_label = ctk.CTkLabel(self, text="Application Settings", font=ctk.CTkFont(size=20, weight="bold"))
        title_label.grid(row=0, column=0, columnspan=2, padx=20, pady=(20,30), sticky="w")

        # PIN Management Section
        pin_management_label = ctk.CTkLabel(self, text="Security PIN:", font=ctk.CTkFont(size=16, weight="bold"))
        pin_management_label.grid(row=1, column=0, padx=20, pady=(10,5), sticky="w")

        self.change_pin_button = ctk.CTkButton(self, text="Change PIN", command=self._handle_change_pin, width=150)
        self.change_pin_button.grid(row=2, column=0, padx=20, pady=5, sticky="w")

        self.update_pin_button_states()
        
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
        save_auto_lock_setting(timeout_seconds)
        messagebox.showinfo("Auto-Lock Updated", f"Auto-lock timeout set to {selected_display_value}.", parent=self.master_app)
        
        # Notify the main app to update its timer
        if hasattr(self.master_app, 'update_auto_lock_and_reset_timer'):
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

            # Serialize token data to JSON string first
            tokens_json_string = json.dumps(all_tokens, indent=4)
            tokens_data_bytes = tokens_json_string.encode('utf-8')

            # Generate salt and nonce (IV for GCM)
            salt = os.urandom(SALT_SIZE_BYTES)
            nonce = os.urandom(AES_NONCE_SIZE_BYTES) # AES-GCM nonce

            # Derive encryption key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE_BYTES,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            aes_key = kdf.derive(backup_password.encode('utf-8'))

            # Encrypt using AES-GCM
            aesgcm = AESGCM(aes_key)
            encrypted_data_bytes = aesgcm.encrypt(nonce, tokens_data_bytes, None) # No associated data

            # Prepare data for saving
            backup_content = {
                "version": "1.0_encrypted",
                "salt": base64.b64encode(salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(encrypted_data_bytes).decode('utf-8')
            }

            with open(backup_file_path, 'w') as f:
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
            with open(restore_file_path, 'r') as f:
                backup_content = json.load(f)

            # Basic check for expected encrypted structure
            if not isinstance(backup_content, dict) or \
               not all(key in backup_content for key in ["version", "salt", "nonce", "ciphertext"]):
                # Try to load as old plaintext format for backward compatibility
                messagebox.showerror("Restore Error", "Invalid or unsupported backup file format.", parent=self.master_app)
                return

            # Get password for decryption
            password_dialog = ctk.CTkInputDialog(text="Enter the password for this backup file:", title="Backup Password")
            backup_password = password_dialog.get_input() # Returns None if cancelled

            if not backup_password:
                messagebox.showinfo("Restore Cancelled", "Password not provided. Restore cancelled.", parent=self.master_app)
                return

            # Decode salt, nonce, and ciphertext from Base64
            salt = base64.b64decode(backup_content["salt"])
            nonce = base64.b64decode(backup_content["nonce"])
            ciphertext = base64.b64decode(backup_content["ciphertext"])

            # Derive decryption key (same as encryption)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE_BYTES,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            aes_key = kdf.derive(backup_password.encode('utf-8'))

            # Decrypt using AES-GCM
            tokens_data_bytes = None
            try:
                aesgcm = AESGCM(aes_key)
                tokens_data_bytes = aesgcm.decrypt(nonce, ciphertext, None) # No associated data
            except Exception as decrypt_error: # Catches InvalidTag from AESGCM if key/tag is wrong
                traceback.print_exc() # Log the detailed error
                messagebox.showerror("Decryption Failed", "Invalid password or corrupted backup file. Please check the password and try again.", parent=self.master_app)
                return

            if not tokens_data_bytes:
                 messagebox.showerror("Decryption Failed", "Decryption resulted in no data. The backup might be corrupted.", parent=self.master_app)
                 return

            tokens_to_restore = json.loads(tokens_data_bytes.decode('utf-8'))

            if not isinstance(tokens_to_restore, list) or not all(isinstance(token, dict) for token in tokens_to_restore):
                messagebox.showerror("Restore Error", "Decrypted data is not in the expected format (list of tokens).", parent=self.master_app)
                return

            if not tokens_to_restore:
                messagebox.showinfo("Restore Tokens", "No tokens found in the (decrypted) backup file.", parent=self.master_app)
                return

            confirm_restore = messagebox.askyesno(
                "Confirm Restore",
                f"Found {len(tokens_to_restore)} token(s) in the backup file.\n\n"
                "Restoring will add tokens from the backup. "
                "If a token with the same issuer and account name already exists, "
                "a new entry may be created (e.g., MyService_user_1) rather than overwriting the existing one directly.\n\n"
                "Do you want to proceed with the restore?",
                parent=self.master_app
            )

            if not confirm_restore:
                return
            
            restored_count = 0
            failed_count = 0
            for token_data in tokens_to_restore:
                account_name = token_data.get("account_name")
                issuer_name = token_data.get("issuer_name")
                secret_key = token_data.get("secret_key")
                token_type = token_data.get("type", "TOTP") # Default to TOTP if missing

                if account_name and issuer_name and secret_key:
                    try:
                        # Ensure secure_storage.save_token_secret handles new tokens and updates correctly
                        # It should generate a new identifier if one isn't present or use existing if one matches
                        # For restore, we usually want to create new entries or overwrite based on some logic.
                        # Current save_token_secret uses issuer+account for identifier if not given.
                        save_token_secret(
                            account_name=account_name,
                            issuer_name=issuer_name,
                            secret_key=secret_key,
                            token_type=token_type
                        )
                        restored_count += 1
                    except Exception as e:
                        # Consider logging specific token that failed
                        print(f"Failed to restore a token: {e}")
                        failed_count += 1
                else:
                    print(f"Skipping token due to missing critical data. Token details: {{'issuer': token_data.get('issuer_name'), 'account': token_data.get('account_name')}}")
                    failed_count += 1
            
            summary_message = f"Restore completed.\n\nSuccessfully restored: {restored_count} token(s).\nFailed to restore: {failed_count} token(s)."
            messagebox.showinfo("Restore Summary", summary_message, parent=self.master_app)

            if hasattr(self.master_app, 'load_and_display_tokens'):
                self.master_app.load_and_display_tokens()

            if hasattr(self.master_app, 'update_auto_lock_and_reset_timer'):
                self.master_app.update_auto_lock_and_reset_timer()

        except json.JSONDecodeError:
            messagebox.showerror("Restore Error", "Invalid JSON file. Could not decode backup data (outer structure).", parent=self.master_app)
        except Exception as e:
            messagebox.showerror("Restore Error", f"An error occurred during restore: {e}", parent=self.master_app)
            traceback.print_exc()

    def update_pin_button_states(self):
        """Enable/disable PIN buttons based on whether a PIN is currently set."""
        if app_lock.is_pin_set():
            self.change_pin_button.configure(state="normal", text="Change PIN") # Set text back
        else:
            self.change_pin_button.configure(state="normal", text="Set PIN") # Change text if no PIN, ensure it's enabled

    def _handle_change_pin(self):
        """Handle PIN change request."""
        if not app_lock.is_pin_set():
            # If no PIN is set, set initial PIN
            self._set_initial_pin()
            return

        # Verify current PIN first
        current_pin_dialog = PinDialog(self.master_app, title="Verify Current PIN", 
                                     prompt="Enter your current PIN to change it:", show_cancel=True)
        current_pin = current_pin_dialog.get_pin()

        if not current_pin:
            return  # User cancelled

        if not app_lock.verify_app_pin(current_pin):
            messagebox.showerror("PIN Verification Failed", 
                               "The current PIN you entered is incorrect.", parent=self.master_app)
            return

        # Current PIN verified, ask for new PIN
        self._set_initial_pin(prompt_message="Enter your new PIN (min. 4 characters):", title="Set New PIN")
        
    def _set_initial_pin(self, prompt_message="Set a new application PIN (min 4 characters):", title="Set Application PIN"):
        """Set or change the application PIN."""
        new_pin_dialog = PinDialog(self.master_app, title=title, 
                                  prompt=prompt_message, 
                                  confirm_pin_mode=True, show_cancel=True)
        new_pin = new_pin_dialog.get_pin()

        if new_pin:
            try:
                app_lock.set_app_pin(new_pin)
                messagebox.showinfo("PIN Updated", "Application PIN has been successfully set/updated.", parent=self.master_app)
            except ValueError as ve:
                messagebox.showerror("PIN Error", str(ve), parent=self.master_app)
            except Exception as e:
                messagebox.showerror("PIN Error", f"Could not set new PIN: {e}", parent=self.master_app)
            finally:
                self.update_pin_button_states()
        else:
            self.update_pin_button_states()  # Ensure buttons are in correct state if user cancels