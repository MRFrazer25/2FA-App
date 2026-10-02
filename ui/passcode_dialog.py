import customtkinter as ctk
import traceback
from core import app_lock

PIN_WARNING = ("A PIN is quicker to type, but much easier to crack than a password "
               "if someone copies your data.")
FORGET_WARNING = ("This encrypts your tokens. If you forget it, they can't be recovered, "
                  "so keep an encrypted backup (Settings > Backup Tokens).")

def _clear_entry(entry: ctk.CTkEntry):
    """Clears a masked entry. CTkEntry loses its masking if an entry that is already showing its
    placeholder is cleared again, so empty entries are left alone."""
    if entry.get():
        entry.delete(0, ctk.END)

class _ModalDialog(ctk.CTkToplevel):
    """Shared setup for the modal PIN/password dialogs."""
    def __init__(self, master, title, show_cancel):
        super().__init__(master)
        self.lift()
        self.attributes("-topmost", True)
        self.grab_set()
        self.resizable(False, False)
        self.title(title)
        self._show_cancel = show_cancel

        self.protocol("WM_DELETE_WINDOW", self._handle_close_button)
        self.after(50, self._center_window)
        # Release topmost after a delay, relying more on grab_set for modality
        self.after(150, lambda: self.attributes("-topmost", False))

    def _add_buttons(self):
        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.pack(padx=20, pady=(10,20), fill="x")
        self.buttons_frame.grid_columnconfigure(0, weight=1)
        if self._show_cancel:
            self.buttons_frame.grid_columnconfigure(1, weight=1)
            self.cancel_button = ctk.CTkButton(self.buttons_frame, text="Cancel", command=self._cancel_event, width=100, fg_color="gray", hover_color="darkgray")
            self.cancel_button.grid(row=0, column=0, padx=(0,5), sticky="ew")
            self.ok_button = ctk.CTkButton(self.buttons_frame, text="OK", command=self._ok_event, width=100)
            self.ok_button.grid(row=0, column=1, padx=(5,0), sticky="ew")
        else:
            self.ok_button = ctk.CTkButton(self.buttons_frame, text="OK", command=self._ok_event, width=100)
            self.ok_button.grid(row=0, column=0, sticky="ew")
        self.bind("<Return>", self._ok_event)

    def _handle_close_button(self):
        if self._show_cancel:
            self._cancel_event()
        else:
            # Mandatory dialogs (initial setup, app unlock): closing the window exits the app.
            self._result = None
            if hasattr(self.master, 'quit_application_if_pin_cancelled') and callable(getattr(self.master, 'quit_application_if_pin_cancelled')):
                 self.master.quit_application_if_pin_cancelled()
            self.grab_release()
            self.destroy()

    def _center_window(self):
        self.update_idletasks() # Ensure window dimensions are calculated
        if self.master and self.master.winfo_exists() and self.master.winfo_viewable():
            master_x = self.master.winfo_x()
            master_y = self.master.winfo_y()
            master_width = self.master.winfo_width()
            master_height = self.master.winfo_height()
            dialog_width = self.winfo_width()
            dialog_height = self.winfo_height()

            # Check for valid dialog dimensions, retry if not ready
            if dialog_width <= 1 or dialog_height <= 1:
                self.after(20, self._center_window)
                return

            x = max(0, master_x + (master_width - dialog_width) // 2)
            y = max(0, master_y + (master_height - dialog_height) // 2)
            self.geometry(f"+{x}+{y}")
        else:
            # Main window is hidden (startup or locked), so center on screen
            self.tk.eval(f'tk::PlaceWindow {self} center')

    def _cancel_event(self, event=None):
        self._result = None
        self.grab_release()
        self.destroy()

    def _finish(self, result):
        self._result = result
        self.grab_release()
        self.destroy()

    def get_result(self):
        self.master.wait_window(self)
        return self._result

class UnlockDialog(_ModalDialog):
    """Asks for the PIN or password and checks it with verify(passcode), which returns
    a truthy result (e.g. the data keys) when correct. get_result() returns that result,
    or None if the dialog was cancelled.

    Wrong attempts are counted by app_lock, which survives restarts. During a lockout
    the dialog shows a countdown and the OK button is disabled."""
    def __init__(self, master, verify, kind=app_lock.KIND_PASSWORD, title="Unlock Application",
                 prompt=None, show_cancel=True):
        super().__init__(master, title, show_cancel)
        self._result = None
        self._verify = verify
        self._kind = kind
        self._countdown_job = None
        name = app_lock.describe(kind)

        self.prompt_label = ctk.CTkLabel(self, text=prompt or f"Enter your {name} to unlock:", wraplength=300, justify="center")
        self.prompt_label.pack(padx=20, pady=(20,10))

        self.passcode_entry = ctk.CTkEntry(self, placeholder_text=f"Enter {name}", show="*", width=250, font=ctk.CTkFont(size=16))
        self.passcode_entry.pack(padx=20, pady=5)

        self.error_label_text = ctk.StringVar()
        self.error_label = ctk.CTkLabel(self, textvariable=self.error_label_text, text_color="red", wraplength=300)
        self.error_label.pack(padx=20, pady=(0,5))

        self._add_buttons()
        self.passcode_entry.after(100, self.passcode_entry.focus_force)
        self._show_lockout(self._seconds_locked_out()) # A lockout may still be running from earlier

    def _seconds_locked_out(self) -> int:
        try:
            return app_lock.seconds_locked_out()
        except Exception:
            traceback.print_exc()
            return 0 # unlock() checks again and reports the error

    def _show_lockout(self, seconds: int):
        """Disables OK and counts down while locked out."""
        if self._countdown_job:
            self.after_cancel(self._countdown_job)
            self._countdown_job = None
        if seconds <= 0:
            self.ok_button.configure(state="normal")
            if self.error_label_text.get().startswith("Too many"):
                self.error_label_text.set("")
            return
        self.ok_button.configure(state="disabled")
        self.error_label_text.set(f"Too many incorrect attempts. Try again in {app_lock.format_wait(seconds)}.")
        self._countdown_job = self.after(1000, lambda: self._show_lockout(self._seconds_locked_out()))

    def destroy(self):
        if self._countdown_job:
            self.after_cancel(self._countdown_job)
            self._countdown_job = None
        super().destroy()

    def _ok_event(self, event=None):
        if self._countdown_job:
            return # Locked out; Enter shouldn't get around the disabled OK button
        passcode = self.passcode_entry.get()
        name = app_lock.describe(self._kind)
        if not passcode:
            self.error_label_text.set(f"{name.capitalize()} cannot be empty.")
            return

        self.error_label_text.set("Checking...")
        self.ok_button.configure(state="disabled")
        self.update_idletasks() # Show "Checking..." while the (deliberately slow) check runs
        try:
            result = self._verify(passcode)
        except app_lock.LockedOutError as e:
            _clear_entry(self.passcode_entry)
            self._show_lockout(e.seconds)
            return
        except Exception as e:
            traceback.print_exc()
            self.ok_button.configure(state="normal")
            self.error_label_text.set(f"Could not check the {name}: {e}")
            return
        if not self.winfo_exists():
            return
        self.ok_button.configure(state="normal")
        if result:
            self._finish(result)
            return

        _clear_entry(self.passcode_entry)
        self.passcode_entry.focus()
        locked_seconds = self._seconds_locked_out()
        if locked_seconds:
            self._show_lockout(locked_seconds)
            return
        message = f"Incorrect {name}."
        try:
            attempts_left = app_lock.attempts_before_lockout()
        except Exception:
            attempts_left = 0
        if attempts_left:
            message += f" {attempts_left} more attempt(s) before you have to wait {app_lock.format_wait(app_lock.LOCKOUT_BASE_SECONDS)}."
        self.error_label_text.set(message)

class SetPasscodeDialog(_ModalDialog):
    """Lets the user choose a PIN or password and enter it twice.
    get_result() returns (kind, passcode), or None if cancelled."""
    def __init__(self, master, title="Set PIN or Password", intro=None, show_cancel=True):
        super().__init__(master, title, show_cancel)
        self._result = None

        if intro:
            self.intro_label = ctk.CTkLabel(self, text=intro, wraplength=320, justify="center")
            self.intro_label.pack(padx=20, pady=(20,5))

        self.kind_selector = ctk.CTkSegmentedButton(self, values=["Password", "PIN"], command=self._on_kind_change)
        self.kind_selector.pack(padx=20, pady=(15 if intro else 20, 5))
        self.kind_selector.set("Password")

        self.rule_label = ctk.CTkLabel(self, text="", text_color="gray", wraplength=320, justify="center")
        self.rule_label.pack(padx=20, pady=(0,5))

        # Placeholders are set once: changing them later inserts the placeholder text into a
        # focused field and turns off masking, which would show the PIN or password as it's typed
        self.passcode_entry = ctk.CTkEntry(self, placeholder_text="Enter PIN or password", show="*", width=250, font=ctk.CTkFont(size=16))
        self.passcode_entry.pack(padx=20, pady=5)
        self.confirm_entry = ctk.CTkEntry(self, placeholder_text="Confirm", show="*", width=250, font=ctk.CTkFont(size=16))
        self.confirm_entry.pack(padx=20, pady=(5,10))

        self.warning_label = ctk.CTkLabel(self, text=FORGET_WARNING, text_color=("#B45309", "#FBBF24"), wraplength=320, justify="center")
        self.warning_label.pack(padx=20, pady=(0,5))

        self.error_label_text = ctk.StringVar()
        self.error_label = ctk.CTkLabel(self, textvariable=self.error_label_text, text_color="red", wraplength=320)
        self.error_label.pack(padx=20, pady=(0,5))

        self._add_buttons()
        self._on_kind_change("Password")
        self.passcode_entry.after(100, self.passcode_entry.focus_force)

    def _selected_kind(self) -> str:
        return app_lock.KIND_PIN if self.kind_selector.get() == "PIN" else app_lock.KIND_PASSWORD

    def _on_kind_change(self, value):
        if self._selected_kind() == app_lock.KIND_PIN:
            self.rule_label.configure(text=f"At least {app_lock.MIN_PIN_LENGTH} digits. {PIN_WARNING}")
        else:
            self.rule_label.configure(text=f"At least {app_lock.MIN_PASSWORD_LENGTH} characters. Recommended.")
        for entry in (self.passcode_entry, self.confirm_entry):
            _clear_entry(entry)
        self.error_label_text.set("")

    def _ok_event(self, event=None):
        kind = self._selected_kind()
        passcode = self.passcode_entry.get()
        try:
            app_lock.validate_passcode(kind, passcode)
        except ValueError as e:
            self.error_label_text.set(str(e))
            self.passcode_entry.focus()
            return
        if passcode != self.confirm_entry.get():
            self.error_label_text.set(f"{app_lock.describe(kind).capitalize()}s do not match.")
            _clear_entry(self.confirm_entry)
            self.confirm_entry.focus()
            return
        self._finish((kind, passcode))
