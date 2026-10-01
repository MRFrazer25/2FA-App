import customtkinter as ctk
import time
import pyperclip # For clipboard functionality
import threading # For delayed clipboard clearing
import traceback # For printing tracebacks
from core import otp
from ui.recovery_codes_dialog import RecoveryCodesDialog # Import the new dialog

CLIPBOARD_CLEAR_SECONDS = 30.0

# There is only one clipboard, so the last copied code is tracked for the whole app
_copied_code = None
_clipboard_clear_timer = None
_clipboard_lock = threading.Lock()

def _copy_code(code: str):
    """Copies a code to the clipboard and schedules it to be cleared."""
    global _copied_code, _clipboard_clear_timer
    pyperclip.copy(code)
    with _clipboard_lock:
        if _clipboard_clear_timer:
            _clipboard_clear_timer.cancel()
        _copied_code = code
        _clipboard_clear_timer = threading.Timer(CLIPBOARD_CLEAR_SECONDS, clear_copied_code)
        _clipboard_clear_timer.daemon = True
        _clipboard_clear_timer.start()

def clear_copied_code():
    """Clears the clipboard now if it still holds the last code copied by the app."""
    global _copied_code, _clipboard_clear_timer
    with _clipboard_lock:
        if _clipboard_clear_timer:
            _clipboard_clear_timer.cancel()
            _clipboard_clear_timer = None
        code, _copied_code = _copied_code, None
    if code is None:
        return
    try:
        if pyperclip.paste() == code:
            pyperclip.copy("")
    except pyperclip.PyperclipException:
        pass

class TokenCard(ctk.CTkFrame):
    """A card widget to display a single 2FA token, its details, and actions."""
    def __init__(self, master, token_identifier: str, account_name: str, secret_key: str, issuer_name: str = None, recovery_codes: str = "",
                 digits: int = otp.DEFAULT_DIGITS, period: int = otp.DEFAULT_PERIOD, algorithm: str = otp.DEFAULT_ALGORITHM,
                 edit_callback=None, delete_callback=None, **kwargs):
        super().__init__(master, **kwargs)

        self.token_identifier = token_identifier # Unique ID from secure_storage
        self.account_name = account_name # User's account name (e.g., email, username)
        self.issuer_name = issuer_name if issuer_name else "Unknown Issuer" # Service/website name
        self.recovery_codes = recovery_codes # Store recovery codes
        self.totp = otp.make_totp(secret_key, digits, period, algorithm)
        self._current_token_val = ""
        self._update_job = None
        self.edit_callback = edit_callback
        self.delete_callback = delete_callback

        self.configure(corner_radius=10, border_width=1)

        # Grid configuration
        self.grid_columnconfigure(0, weight=1) # Column for labels and token
        self.grid_columnconfigure(1, weight=0) # Progress bar spacer (or part of token column)
        self.grid_columnconfigure(2, weight=0) # Buttons column

        # Info Frame (Issuer, Account Name, Token)
        self.info_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.info_frame.grid(row=0, column=0, sticky="ew", padx=(15,5), pady=(10,0))
        self.info_frame.grid_columnconfigure(0, weight=1)

        self.issuer_label = ctk.CTkLabel(self.info_frame, text=f"{self.issuer_name}", font=ctk.CTkFont(size=12, slant="italic"))
        self.issuer_label.grid(row=0, column=0, sticky="w")
        self.account_name_label = ctk.CTkLabel(self.info_frame, text=f"{self.account_name}", font=ctk.CTkFont(size=16, weight="bold"))
        self.account_name_label.grid(row=1, column=0, sticky="w")

        self.token_label = ctk.CTkLabel(self.info_frame, text="-" * digits, font=ctk.CTkFont(size=28, weight="bold"))
        self.token_label.grid(row=2, column=0, pady=(0,5), sticky="w")

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal", mode="determinate")
        self.progress_bar.set(1)
        # Place progress bar below the info frame, spanning relevant columns for data display
        self.progress_bar.grid(row=1, column=0, columnspan=2, padx=15, pady=(0,10), sticky="ew")

        # Buttons Frame (Copy, Edit, Delete)
        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.grid(row=0, column=2, rowspan=2, sticky="nse", padx=(5,15), pady=5)
        self.buttons_frame.grid_columnconfigure(0, weight=0)

        self.copy_button = ctk.CTkButton(self.buttons_frame, text="Copy", width=30, height=30, command=self.copy_to_clipboard)
        self.copy_button.grid(row=0, column=0, pady=(5,2), sticky="ew")

        self.view_codes_button = ctk.CTkButton(self.buttons_frame, text="View Codes", command=self._show_recovery_codes, width=30, height=30)
        self.view_codes_button.grid(row=1, column=0, pady=2, sticky="ew")
        # Disable button if no recovery codes are present
        if not self.recovery_codes:
            self.view_codes_button.configure(state=ctk.DISABLED)

        if self.edit_callback:
            self.edit_button = ctk.CTkButton(self.buttons_frame, text="Edit", width=30, height=30, command=self._on_edit)
            self.edit_button.grid(row=2, column=0, pady=(2,5), sticky="ew")

        if self.delete_callback:
            self.delete_button = ctk.CTkButton(self.buttons_frame, text="Del", width=30, height=30, command=self._on_delete, fg_color="#D32F2F", hover_color="#B71C1C")
            self.delete_button.grid(row=3, column=0, pady=(2,5), sticky="ew")

        self.update_token()

    def update_token(self):
        self._update_job = None
        try:
            self._current_token_val = self.totp.now()
            self.token_label.configure(text=otp.format_code(self._current_token_val))

            time_remaining = self.totp.interval - (time.time() % self.totp.interval)
            progress = time_remaining / self.totp.interval
            self.progress_bar.set(progress)

            self._update_job = self.after(1000, self.update_token)
        except Exception as e:
            print(f"Error in TokenCard update_token: {e}")
            traceback.print_exc()

    def destroy(self):
        # Cancel the pending refresh so it doesn't fire on a destroyed widget
        if self._update_job:
            self.after_cancel(self._update_job)
            self._update_job = None
        super().destroy()

    def copy_to_clipboard(self):
        if self._current_token_val:
            try:
                _copy_code(self._current_token_val)
                self.copy_button.configure(text="OK!")
                self.copy_button.after(1500, lambda: self.copy_button.configure(text="Copy"))
            except pyperclip.PyperclipException:
                self.copy_button.configure(text="Err")
                self.copy_button.after(1500, lambda: self.copy_button.configure(text="Copy"))

    def _on_edit(self):
        if self.edit_callback:
            self.edit_callback(self.token_identifier)

    def _on_delete(self):
        if self.delete_callback:
            self.delete_callback(self.token_identifier, f"{self.issuer_name} ({self.account_name})")

    def _show_recovery_codes(self):
        if self.recovery_codes:
            title = f"Recovery Codes for {self.issuer_name} ({self.account_name})"
            dialog = RecoveryCodesDialog(self.master, title=title, recovery_codes=self.recovery_codes)
            dialog.show() # This will make it modal and wait
        else:
            # This case should ideally be prevented by the button being disabled,
            # but as a fallback:
            from tkinter import messagebox # Import only if needed for this specific fallback
            messagebox.showinfo("No Recovery Codes", "No recovery codes are stored for this token.", parent=self.master)
