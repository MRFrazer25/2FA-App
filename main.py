import customtkinter as ctk
import tkinter as tk
from ui.token_card import TokenCard, clear_copied_code
from core import secure_storage
from ui.add_token_dialog import AddTokenDialog
import tkinter.messagebox as messagebox
from ui.passcode_dialog import UnlockDialog, SetPasscodeDialog
from core import app_lock
import sys
import keyring
import traceback
from ui.sidebar import SidebarFrame

MAX_PIN_ATTEMPTS = 3
NO_TOKENS_TEXT = "No 2FA tokens found. Click 'Add Token' in the sidebar to add one."

class TwoFactorApp(ctk.CTk):
    """
    Main application class for the 2FA App.
    Handles PIN/password protection and encryption, token management (add, edit, delete, display),
    auto-lock functionality, and navigation between different views (home, settings).
    """
    def __init__(self):
        super().__init__()
        self.withdraw()

        self.app_unlocked = False
        self.last_active_frame_before_lock = None
        self.inactivity_timer_id = None
        self.auto_lock_after_seconds = secure_storage.get_auto_lock_setting()

        # Configure main window grid
        self.grid_columnconfigure(0, weight=0)  # Sidebar column
        self.grid_columnconfigure(1, weight=1)  # Content column
        self.grid_rowconfigure(0, weight=1)     # Main content row

        # Main UI Structure
        # Sidebar
        self.sidebar_frame = SidebarFrame(self,
                                          add_token_callback=self.open_add_token_dialog,
                                           show_settings_callback=lambda: self._show_frame_callback("Settings"),
                                           show_home_callback=lambda: self._show_frame_callback("Home"),
                                           lock_app_callback=self.lock_application)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        # Content container
        self.content_container = ctk.CTkFrame(self, fg_color="transparent")
        self.content_container.grid(row=0, column=1, sticky="nsew")
        self.content_container.grid_rowconfigure(0, weight=1)
        self.content_container.grid_columnconfigure(0, weight=1)

        # Frame dictionary
        self.frames = {}

        # Home Frame container
        self.home_frame_container = ctk.CTkFrame(self.content_container, fg_color="transparent")
        
        # Setup inside home_frame_container for tokens
        self.home_frame_container.grid_rowconfigure(0, weight=0) # For search bar
        self.home_frame_container.grid_rowconfigure(1, weight=1) # For token list/scrollable frame
        self.home_frame_container.grid_columnconfigure(0, weight=1) # For Search Entry

        # Add Search Bar
        # No textvariable: CTkEntry doesn't show placeholder text when one is set
        self.search_entry = ctk.CTkEntry(self.home_frame_container, 
                                          placeholder_text="Search tokens (by issuer or account)...",
                                          height=35, font=ctk.CTkFont(size=14))
        self.search_entry.grid(row=0, column=0, padx=10, pady=(10,5), sticky="ew")
        self.search_entry.bind("<KeyRelease>", self._filter_tokens_by_search) # Filter as the user types
        self.token_scrollable_frame = ctk.CTkScrollableFrame(self.home_frame_container, fg_color="transparent")
        # Grid for token_scrollable_frame will be managed by load_and_display_tokens

        self.no_tokens_label = ctk.CTkLabel(self.home_frame_container,
                                             text=NO_TOKENS_TEXT,
                                             font=ctk.CTkFont(size=16),
                                             text_color="gray")
        # Grid for no_tokens_label will be managed by load_and_display_tokens

        self.frames[SidebarFrame] = self.sidebar_frame

        if not self._handle_initial_pin_check():
            return

        if self.app_unlocked:
            self.after(100, self.show_app_window)
        else:
            if not self.winfo_viewable(): # Check if it was withdrawn
                self.withdraw()

        self.title("2FA App")
        self.geometry("1024x768")

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # Ensure these are NOT reset to None after creation
        self.token_cards = {} # Holds active TokenCard widgets
        self.current_display_frame = None # Tracks the currently displayed frame in content_container

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Bind activity events
        self.bind_all("<Motion>", self.reset_inactivity_timer)
        self.bind_all("<KeyPress>", self.reset_inactivity_timer)
        self.bind_all("<Button-1>", self.reset_inactivity_timer)

    def show_app_window(self):
        """Finalizes app window setup after successful unlock and shows it."""
        self.auto_lock_after_seconds = secure_storage.get_auto_lock_setting()
        self.deiconify()
        self.show_home_frame() # Show initial frame
        self.reset_inactivity_timer() # Start inactivity timer once app is shown

    def _on_closing(self):
        if self.inactivity_timer_id:
            self.after_cancel(self.inactivity_timer_id)
            self.inactivity_timer_id = None

        clear_copied_code()
        self.destroy()

    def quit_application_if_pin_cancelled(self):
        messagebox.showerror("Unlock Required", "Application access denied. Exiting.", parent=self if self.winfo_exists() else None)
        if hasattr(self, 'destroy') and self.winfo_exists():
            self.destroy()
        sys.exit(1)

    def _exit_after_failed_unlock(self, dialog) -> bool:
        if dialog.attempts_exhausted:
            messagebox.showerror("Access Denied", "Maximum attempts reached. Exiting.", parent=self)
        self.quit_application_if_pin_cancelled() # This will exit
        return False

    def _unlock_with_data_key(self, data_key: bytes):
        """Makes the tokens readable, and encrypts any saved before encryption was added."""
        secure_storage.set_data_key(data_key)
        try:
            secure_storage.migrate_plaintext_tokens()
        except Exception:
            # Unencrypted tokens can still be read; migration is retried on the next unlock
            traceback.print_exc()
        self.app_unlocked = True

    def _prompt_for_pin_and_unlock(self, is_startup_check: bool) -> bool:
        dialog = UnlockDialog(self, verify=app_lock.unlock, kind=app_lock.passcode_kind(),
                              max_attempts=MAX_PIN_ATTEMPTS, show_cancel=not is_startup_check)
        data_key = dialog.get_result()
        if not data_key:
            return self._exit_after_failed_unlock(dialog)
        self._unlock_with_data_key(data_key)
        return True

    def _set_up_passcode(self) -> bool:
        """First launch: choose a PIN or password, which creates the key that encrypts tokens."""
        dialog = SetPasscodeDialog(self, title="Welcome to 2FA App",
                                   intro="Choose a PIN or password. It's needed to open the app and is used to encrypt your 2FA tokens.",
                                   show_cancel=False)
        result = dialog.get_result()
        if not result:
            self.quit_application_if_pin_cancelled() # This will exit
            return False
        self._unlock_with_data_key(app_lock.create_vault(*result))
        return True

    def _upgrade_legacy_pin(self) -> bool:
        """Upgrades a PIN from before encryption was added: checks it, then uses it, or a new
        PIN or password if it's too short, to encrypt the tokens."""
        dialog = UnlockDialog(self, verify=lambda pin: pin if app_lock.verify_legacy_pin(pin) else None, kind=app_lock.KIND_PIN,
                              max_attempts=MAX_PIN_ATTEMPTS, show_cancel=False)
        pin = dialog.get_result()
        if not pin:
            return self._exit_after_failed_unlock(dialog)

        kind = app_lock.legacy_pin_kind(pin)
        if kind:
            data_key = app_lock.create_vault(kind, pin)
            message = f"Your tokens are now encrypted with your {app_lock.describe(kind)}. If you forget it, they can't be recovered, so keep an encrypted backup (Settings > Backup Tokens)."
        else:
            setup_dialog = SetPasscodeDialog(self, title="Choose a Stronger PIN or Password",
                                             intro=f"Your tokens are now encrypted with your PIN or password. Your current PIN is too short for this, "
                                                   f"so please choose a new PIN ({app_lock.MIN_PIN_LENGTH}+ digits) or password ({app_lock.MIN_PASSWORD_LENGTH}+ characters).",
                                             show_cancel=False)
            result = setup_dialog.get_result()
            if not result:
                self.quit_application_if_pin_cancelled() # This will exit
                return False
            data_key = app_lock.create_vault(*result)
            message = "Your tokens are now encrypted."

        self._unlock_with_data_key(data_key)
        messagebox.showinfo("Tokens Encrypted", message, parent=self)
        return True

    def _handle_initial_pin_check(self) -> bool:
        try:
            if app_lock.has_vault():
                return self._prompt_for_pin_and_unlock(is_startup_check=True)
            if app_lock.has_legacy_pin():
                return self._upgrade_legacy_pin()
            return self._set_up_passcode()
        except keyring.errors.NoKeyringError:
            messagebox.showerror("Keyring Error", "A keyring backend is required for secure storage. Please ensure one is installed and configured for your system. See README for details.", parent=self if self.winfo_exists() else None)
            if hasattr(self, 'destroy') and self.winfo_exists(): self.destroy()
            sys.exit(1) # Critical error, cannot proceed
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Startup Error", f"An unexpected error occurred while unlocking: {e}. Exiting.", parent=self if self.winfo_exists() else None)
            if hasattr(self, 'destroy') and self.winfo_exists(): self.destroy()
            sys.exit(1) # Critical error, cannot proceed

    def _show_frame_callback(self, frame_class_name: str):
        """Shows the specified frame. Frame_class_name should be 'Home' or 'Settings'."""
        if self.app_unlocked: # Ensure app is unlocked before switching frames
            if frame_class_name == "Home":
                self.show_home_frame()
            elif frame_class_name == "Settings":
                from ui.settings_frame import SettingsFrame
                if SettingsFrame not in self.frames or self.frames[SettingsFrame] is None or not self.frames[SettingsFrame].winfo_exists():
                    settings_frame_instance = SettingsFrame(self.content_container, app_instance=self)
                    self.frames[SettingsFrame] = settings_frame_instance

                settings_instance = self.frames[SettingsFrame]
                self.show_frame(settings_instance)
        else:
            # This case should ideally not be used if UI elements triggering this are disabled when locked.
            pass

    def show_frame(self, frame_instance_to_show):
        if frame_instance_to_show is None:
            return
        
        # Hide the currently displayed frame if it's different from the home_frame_container and not the target
        if self.current_display_frame is not None and self.current_display_frame != self.home_frame_container:
            if self.current_display_frame.winfo_ismapped():
                self.current_display_frame.grid_forget()
        
        # Also, specifically hide home_frame_container if we are showing a different frame
        if frame_instance_to_show != self.home_frame_container:
            if self.home_frame_container.winfo_ismapped():
                self.home_frame_container.grid_forget()

        self.current_display_frame = frame_instance_to_show # Assign the instance
        self.current_display_frame.grid(row=0, column=0, sticky="nsew")

    def show_home_frame(self):
        """Shows the home frame (token display area) and loads tokens."""
        # Hide all other frames in content_container before showing home_frame_container
        for frame_key, frame_instance in self.frames.items():
            if frame_key != SidebarFrame: # Don't hide sidebar
                 if hasattr(frame_instance, 'master') and frame_instance.master == self.content_container: # Ensure we only hide frames within the content_container
                    if frame_instance.winfo_ismapped():
                         frame_instance.grid_forget()

        self.home_frame_container.grid(row=0, column=0, sticky="nsew")
        self.home_frame_container.tkraise()
        self.load_and_display_tokens() # Call to load tokens

    def open_add_token_dialog(self, token_identifier_to_edit: str = None):
        if token_identifier_to_edit:
            token_to_edit = secure_storage.get_token_secret(token_identifier_to_edit)
            if not token_to_edit:
                messagebox.showerror("Edit Error", "Could not load this token to edit.", parent=self)
                return

            dialog = AddTokenDialog(master=self, existing_data=token_to_edit)
            new_data = dialog.get_input()

            if new_data:
                try:
                    # Update the token using its identifier.
                    secure_storage.save_token_secret(identifier=token_identifier_to_edit, **new_data)
                    messagebox.showinfo("Token Updated", 
                                        f"Token for {new_data['issuer_name']} ({new_data['account_name']}) updated successfully.",
                                        parent=self)
                    self.load_and_display_tokens() # Refresh the list
                except ValueError as ve: 
                    messagebox.showerror("Update Error", f"Could not update token: {ve}", parent=self)
                except Exception as e:
                    traceback.print_exc()
                    messagebox.showerror("Update Error", f"An unexpected error occurred while updating the token: {e}", parent=self)
            else:
                pass # Dialog was cancelled
            return

        # Adding a new token (this part is only reached if not editing)
        dialog = AddTokenDialog(master=self) # master should be the main app window
        token_data = dialog.get_input() # This makes the dialog modal and waits

        if token_data:
            try:
                secure_storage.save_token_secret(**token_data) # Generates a new identifier
                messagebox.showinfo("Token Added", 
                                    f"Token for {token_data['issuer_name']} ({token_data['account_name']}) added successfully.",
                                    parent=self)
                self.load_and_display_tokens() # Refresh the list to show the new token
            except ValueError as ve: # Catch specific errors from save_token_secret if any (e.g., duplicate)
                messagebox.showerror("Save Error", f"Could not save token: {ve}", parent=self)
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror("Save Error", f"An unexpected error occurred while saving the token: {e}", parent=self)
        else:
            pass # Dialog was cancelled
    
    def handle_delete_token(self, token_identifier: str, display_name: str):
        confirm = messagebox.askyesno("Confirm Delete", 
                                      f"Are you sure you want to delete the token for\n'{display_name}'?",
                                        parent=self)
        if confirm:
            try:
                secure_storage.delete_token_secret(token_identifier)
                messagebox.showinfo("Token Deleted", f"Token for '{display_name}' has been deleted.", parent=self)
                self.load_and_display_tokens() # Refresh the list
            except Exception as e:
                messagebox.showerror("Delete Error", f"Could not delete token: {e}", parent=self)
                traceback.print_exc()
        else:
            pass # Deletion cancelled

    def _destroy_token_cards(self):
        for card in self.token_cards.values():
            card.destroy()
        self.token_cards.clear()

    def load_and_display_tokens(self):
        """Reloads all tokens from secure storage, rebuilds the token cards, and applies the search filter."""
        self._destroy_token_cards()

        try:
            all_tokens = secure_storage.get_all_token_data()
        except Exception:
            traceback.print_exc()
            self.search_entry.grid_remove()
            self.token_scrollable_frame.grid_forget()
            self.no_tokens_label.configure(text="Error loading tokens.\nCheck logs for details.")
            self.no_tokens_label.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
            return

        for token_data in all_tokens:
            identifier = token_data['identifier']
            self.token_cards[identifier] = TokenCard(
                master=self.token_scrollable_frame,
                token_identifier=identifier,
                account_name=token_data['account_name'],
                secret_key=token_data['secret_key'],
                issuer_name=token_data['issuer_name'],
                recovery_codes=token_data.get('recovery_codes', ''),
                digits=token_data['digits'],
                period=token_data['period'],
                algorithm=token_data['algorithm'],
                edit_callback=self.open_add_token_dialog,
                delete_callback=self.handle_delete_token
            )
        self._filter_tokens_by_search()

    def _filter_tokens_by_search(self, *args):
        """Shows only the already-loaded token cards that match the search text."""
        self.token_scrollable_frame.grid_forget()
        self.no_tokens_label.grid_forget()

        if not self.token_cards:
            self.search_entry.grid_remove() # Hide search if no tokens at all
            self.no_tokens_label.configure(text=NO_TOKENS_TEXT)
            self.no_tokens_label.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
            return
        self.search_entry.grid()

        search_text = self.search_entry.get()
        search_term = search_text.strip().lower()
        displayed_tokens_count = 0
        for card in self.token_cards.values():
            card.pack_forget()
            if search_term in card.issuer_name.lower() or search_term in card.account_name.lower():
                card.pack(pady=10, padx=10, fill="x", expand=True)
                displayed_tokens_count += 1

        if displayed_tokens_count:
            self.token_scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        else:
            self.no_tokens_label.configure(text=f"No tokens found matching '{search_text}'.")
            self.no_tokens_label.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)

    def reset_inactivity_timer(self, event=None): # event arg needed for bindings
        if self.inactivity_timer_id:
            self.after_cancel(self.inactivity_timer_id)
            self.inactivity_timer_id = None
        
        if self.app_unlocked and self.auto_lock_after_seconds > 0:
            self.inactivity_timer_id = self.after(self.auto_lock_after_seconds * 1000, self.lock_application)

    def lock_application(self):
        """Locks the application, withdraws the window, and prompts for the PIN or password to unlock."""
        if self.inactivity_timer_id:
            self.after_cancel(self.inactivity_timer_id)
            self.inactivity_timer_id = None

        self.app_unlocked = False
        self._close_open_dialogs()
        clear_copied_code()
        self.withdraw()
        # Drop decrypted secrets from memory until the app is unlocked again
        self._destroy_token_cards()
        secure_storage.clear_data_key()

        try:
            unlocked = self._prompt_for_pin_and_unlock(is_startup_check=False)
        except Exception as e:
            # Fail closed: without this the window would stay hidden with no way to unlock it
            traceback.print_exc()
            messagebox.showerror("Unlock Error", f"An unexpected error occurred while unlocking: {e}. Exiting.", parent=self)
            self.destroy()
            sys.exit(1)

        if unlocked:
            self.deiconify() # Show the main window again
            self.show_home_frame()
            self.reset_inactivity_timer() # Restart inactivity timer

    def _close_open_dialogs(self):
        """Destroys any open dialog windows so their contents (e.g. secret keys or
        recovery codes) aren't left on screen while the app is locked."""
        pending = list(self.winfo_children())
        while pending:
            widget = pending.pop()
            if isinstance(widget, tk.Toplevel):
                widget.destroy()
            else:
                pending.extend(widget.winfo_children())

    def update_auto_lock_and_reset_timer(self):
        """Called from settings to update the auto-lock timeout and reset the current timer."""
        new_timeout = secure_storage.get_auto_lock_setting()
        self.auto_lock_after_seconds = new_timeout
        self.reset_inactivity_timer() # This will cancel existing and start new if conditions met

if __name__ == "__main__":
    app = None # Initialize app to None
    try:
        app = TwoFactorApp()
        # Only run mainloop if app was successfully initialized and unlocked
        if hasattr(app, 'app_unlocked') and app.app_unlocked and hasattr(app, 'mainloop'):
            app.mainloop()
        # If app.app_unlocked is False here, it means unlocking was cancelled or failed during startup,
        # and the app should have exited via sys.exit in _handle_initial_pin_check.
        # No explicit else needed here if sys.exit is reliably called.
    except Exception as e:
        # General exception catch for unforeseen issues during app init or mainloop
        traceback.print_exc()
        error_message = f"A critical error occurred: {e}. Please check logs."

        # Try to show an error message box
        try:
            if app and app.winfo_exists(): # Check if app and its window exist
                 messagebox.showerror("Critical Error", error_message, parent=app)
            else: # If GUI is not available, print to console (already done by traceback)
                 print(error_message, file=sys.stderr) # Ensure it goes to stderr
        except Exception as msg_e: # If even showing messagebox fails
            print(f"Failed to show error messagebox: {msg_e}", file=sys.stderr)

        # Attempt to clean up the app window if it exists
        if app and hasattr(app, 'destroy') and app.winfo_exists():
            try:
                app.destroy()
            except Exception as destroy_e:
                print(f"Error during app.destroy(): {destroy_e}", file=sys.stderr)
        sys.exit(1) # Exit with an error code