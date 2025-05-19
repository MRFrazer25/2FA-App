import customtkinter as ctk
from ui.token_card import TokenCard
from core import secure_storage
from ui.add_token_dialog import AddTokenDialog
import tkinter.messagebox as messagebox
from ui.pin_dialog import PinDialog
from core import app_lock
import sys
import keyring
import traceback
from ui.sidebar import SidebarFrame

MAX_PIN_ATTEMPTS = 3

class TwoFactorApp(ctk.CTk):
    """
    Main application class for the 2FA App.
    Handles PIN protection, token management (add, edit, delete, display),
    auto-lock functionality, and navigation between different views (home, settings).
    """
    def __init__(self):
        super().__init__()
        self.withdraw()

        self.app_unlocked = False
        self.pin_attempts = 0
        self.last_active_frame_before_lock = None # Used to restore view before lock
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
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(self.home_frame_container, 
                                          textvariable=self.search_var,
                                          placeholder_text="Search tokens (by issuer or account)...",
                                          height=35, font=ctk.CTkFont(size=14))
        self.search_entry.grid(row=0, column=0, padx=10, pady=(10,5), sticky="ew")
        self.search_var.trace_add("write", self._filter_tokens_by_search) # Call filter on text change
        self.token_scrollable_frame = ctk.CTkScrollableFrame(self.home_frame_container, fg_color="transparent")
        # Grid for token_scrollable_frame will be managed by load_and_display_tokens

        self.no_tokens_label = ctk.CTkLabel(self.home_frame_container,
                                             text="No 2FA tokens found. Click 'Add Token' in the sidebar to add one.",
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

        for card_identifier in list(self.token_cards.keys()):
            card = self.token_cards.pop(card_identifier, None)
            if card and card.clipboard_clear_timer and card.clipboard_clear_timer.is_alive(): # Check if timer attribute exists and is alive
                card.clipboard_clear_timer.cancel()
        self.destroy()

    def quit_application_if_pin_cancelled(self):
        messagebox.showerror("PIN Required", "Application access denied. Exiting.", parent=self if self.winfo_exists() else None)
        if hasattr(self, 'destroy') and self.winfo_exists():
            self.destroy()
        sys.exit(1)

    def _prompt_for_pin_and_unlock(self, is_startup_check: bool) -> bool:
        self.pin_attempts = 0
        while self.pin_attempts < MAX_PIN_ATTEMPTS:
            prompt_message = "Enter PIN to unlock"
            if not is_startup_check:
                prompt_message = "Enter PIN to unlock application"
            
            if self.pin_attempts > 0:
                prompt_message = f"Invalid PIN. {prompt_message} ({MAX_PIN_ATTEMPTS - self.pin_attempts} attempts left):"
            else:
                prompt_message = f"{prompt_message} ({MAX_PIN_ATTEMPTS - self.pin_attempts} attempts left):"

            # PinDialog class needs to be available
            pin_dialog = PinDialog(self, title="Unlock Application", prompt=prompt_message, show_cancel=not is_startup_check)
            pin = pin_dialog.get_pin()

            if pin and app_lock.verify_app_pin(pin):
                self.app_unlocked = True
                return True
            elif pin is None and not is_startup_check: # User cancelled PIN prompt for lock screen
                self.quit_application_if_pin_cancelled() # This will exit
                return False
            elif pin is None and is_startup_check: # User cancelled initial PIN prompt
                self.quit_application_if_pin_cancelled() # This will exit
                return False

            self.pin_attempts += 1
            
        messagebox.showerror("Access Denied", "Maximum PIN attempts reached. Exiting.", parent=self)
        self.quit_application_if_pin_cancelled() # This will exit
        return False

    def _handle_initial_pin_check(self) -> bool:
        try:
            if not app_lock.is_pin_set():
                dialog_title = "Set Application PIN"
                dialog_prompt = "Welcome! Please set a PIN for application access (min. 4 characters)."
                pin_dialog = PinDialog(self, title=dialog_title, prompt=dialog_prompt, confirm_pin_mode=True, show_cancel=False)
                pin = pin_dialog.get_pin()

                if pin:
                    try:
                        app_lock.set_app_pin(pin)
                        messagebox.showinfo("PIN Set", "Application PIN has been set successfully.", parent=self)
                        self.app_unlocked = True
                        return True
                    except ValueError as ve:
                        messagebox.showerror("PIN Error", str(ve), parent=self)
                        self.quit_application_if_pin_cancelled()
                        return False # Ensure return after quit
                    except Exception as e:
                        traceback.print_exc()
                        messagebox.showerror("PIN Error", f"Could not set PIN: {e}", parent=self)
                        self.quit_application_if_pin_cancelled()
                        return False # Ensure return after quit
                else: 
                    messagebox.showinfo("PIN Setup Required", "Application PIN setup was cancelled. Exiting.", parent=self)
                    self.quit_application_if_pin_cancelled()
                    return False
            else: 
                return self._prompt_for_pin_and_unlock(is_startup_check=True)
                
        except keyring.errors.NoKeyringError:
            messagebox.showerror("Keyring Error", "A keyring backend is required for PIN storage. Please ensure one is installed and configured for your system. See README for details.", parent=self if self.winfo_exists() else None)
            if hasattr(self, 'destroy') and self.winfo_exists(): self.destroy()
            sys.exit(1) # Critical error, cannot proceed
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Startup Error", f"An unexpected error occurred during PIN check: {e}. Exiting.", parent=self if self.winfo_exists() else None)
            if hasattr(self, 'destroy') and self.winfo_exists(): self.destroy()
            sys.exit(1) # Critical error, cannot proceed

    def _show_frame_callback(self, frame_class_name: str):
        """Shows the specified frame. Frame_class_name should be 'Home' or 'Settings'."""
        if self.app_unlocked: # Ensure app is unlocked before switching frames
            if frame_class_name == "Home":
                self.show_home_frame()
            elif frame_class_name == "Settings":
                from ui.settings_frame import SettingsFrame # Import here for lazy loading & updated path
                if SettingsFrame not in self.frames or self.frames[SettingsFrame] is None or not self.frames[SettingsFrame].winfo_exists():
                    settings_frame_instance = SettingsFrame(self.content_container, app_instance=self) # Pass app_instance
                    self.frames[SettingsFrame] = settings_frame_instance

                settings_instance = self.frames[SettingsFrame]
                self.show_frame(settings_instance)
            # Add other frame navigation logic here if needed
        else:
            # This case should ideally not be hit if UI elements triggering this are disabled when locked.
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
                messagebox.showerror("Edit Error", f"Could not find token data for '{token_identifier_to_edit}' to edit.", parent=self)
                return

            # Pass the existing token type if available, otherwise AddTokenDialog might assume default
            dialog = AddTokenDialog(master=self, existing_data=token_to_edit, current_type=token_to_edit.get('type', 'TOTP'))
            new_data = dialog.get_input()

            if new_data:
                try:
                    # Update the token using its identifier. Token type is implicitly handled as TOTP as it's not editable in the dialog.
                    secure_storage.save_token_secret(account_name=new_data['account_name'], 
                                                    issuer_name=new_data['issuer_name'],
                                                    secret_key=new_data['secret_key'],
                                                    identifier=token_identifier_to_edit,
                                                    recovery_codes=new_data.get('recovery_codes', ''))
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
                # The identifier is generated by secure_storage.save_token_secret based on issuer/account
                secure_storage.save_token_secret(
                    account_name=token_data['account_name'],
                    issuer_name=token_data['issuer_name'],
                    secret_key=token_data['secret_key'],
                    recovery_codes=token_data.get('recovery_codes', '')
                )
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

    def load_and_display_tokens(self):
        for card_identifier, card_widget in list(self.token_cards.items()):
            if card_widget.winfo_exists():
                card_widget.destroy()

        self.token_cards.clear() # Clear the dictionary before repopulating

        self.token_scrollable_frame.grid_forget() # Hide scrollable frame initially
        self.no_tokens_label.grid_forget()    # Hide no_tokens label initially

        search_term = self.search_var.get().lower() if hasattr(self, 'search_var') else ""

        try:
            token_identifiers = secure_storage.get_all_token_identifiers()

            if not token_identifiers:
                self.search_entry.grid_remove() # Hide search if no tokens at all
                self.no_tokens_label.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
                return
            else:
                # Ensure search bar is visible if there are tokens
                self.search_entry.grid()

            displayed_tokens_count = 0
            self.token_scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
            
            for identifier in token_identifiers:
                token_data = secure_storage.get_token_secret(identifier)
                if token_data:
                    issuer_name = token_data.get('issuer_name', 'N/A').lower()
                    account_name = token_data.get('account_name', 'N/A').lower()

                    if search_term in issuer_name or search_term in account_name:
                        card = TokenCard(
                            master=self.token_scrollable_frame,
                            token_identifier=identifier,
                            account_name=token_data.get('account_name', 'N/A'),
                            secret_key=token_data.get('secret_key', ''),
                            issuer_name=token_data.get('issuer_name', 'N/A'),
                            recovery_codes=token_data.get('recovery_codes', ''),
                            edit_callback=self.open_add_token_dialog,
                            delete_callback=self.handle_delete_token
                                     )
                        card.pack(pady=10, padx=10, fill="x", expand=True)
                        self.token_cards[identifier] = card
                        displayed_tokens_count += 1
                else:
                    # If get_token_secret returns None, it might indicate an issue.
                    # secure_storage.py's get_token_secret already logs a warning.
                    print(f"Warning: Token data for identifier '{identifier}' not found or invalid.") # Optional: for direct app log
            
            if displayed_tokens_count == 0: # No tokens matched search, or all failed to load
                self.token_scrollable_frame.grid_forget() # Ensure it's hidden
                if search_term: # If search was active, show specific message
                    self.no_tokens_label.configure(text=f"No tokens found matching '{self.search_var.get()}'.")
                else: # No tokens in general (but there were identifiers, meaning they failed to load or filter)
                     self.no_tokens_label.configure(text="No 2FA tokens to display.\nAdd one or check search filter.")
                self.no_tokens_label.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)

        except Exception as e:
            traceback.print_exc()
            self.token_scrollable_frame.grid_forget()
            self.no_tokens_label.configure(text="Error loading tokens.\nCheck logs for details.")
            self.no_tokens_label.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)

    def _filter_tokens_by_search(self, *args):
        """Callback for the search entry; reloads tokens to apply the filter."""
        self.load_and_display_tokens()

    def reset_inactivity_timer(self, event=None): # event arg needed for bindings
        if self.inactivity_timer_id:
            self.after_cancel(self.inactivity_timer_id)
            self.inactivity_timer_id = None
        
        if self.app_unlocked and self.auto_lock_after_seconds > 0:
            self.inactivity_timer_id = self.after(self.auto_lock_after_seconds * 1000, self.lock_application)

    def lock_application(self):
        """Locks the application, withdraws the window, and prompts for PIN to unlock."""
        if self.inactivity_timer_id:
            self.after_cancel(self.inactivity_timer_id)
            self.inactivity_timer_id = None

        self.app_unlocked = False
        self.withdraw()

        if self._prompt_for_pin_and_unlock(is_startup_check=False):
            self.deiconify() # Show the main window again
            self.show_home_frame()
            self.reset_inactivity_timer() # Restart inactivity timer

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
        # If app.app_unlocked is False here, it means PIN was cancelled or failed during startup,
        # and the app should have exited via sys.exit in _handle_initial_pin_check.
        # No explicit else needed here if sys.exit is reliably called.
    except Exception as e:
        # General exception catch for unforeseen issues during app init or mainloop
        traceback.print_exc()
        error_message = f"A critical error occurred: {e}. Please check logs."

        # Try to show an error message box if possible
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