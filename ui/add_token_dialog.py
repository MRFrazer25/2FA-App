import customtkinter as ctk
from PIL import Image, ImageGrab
from core import otp
from core.secure_storage import normalize_secret_key

SCREEN_CAPTURE_DELAY_MS = 300 # Time for the app's windows to disappear before the screen is captured

class AddTokenDialog(ctk.CTkToplevel):
    """Dialog for adding a new token or editing an existing one.
    A token can be filled in by scanning a QR code on screen, opening a QR code image,
    or pasting an otpauth:// link into the Secret Key field."""
    def __init__(self, master=None, existing_data: dict = None):
        super().__init__(master)

        self.is_edit_mode = bool(existing_data)

        if self.is_edit_mode:
            self.title("Edit Token")
        else:
            self.title("Add New Token")

        self.lift()  # Lift window on top
        self.attributes("-topmost", True) # Keep on top
        self.grab_set() # Make modal
        self.resizable(False, False)

        self._user_input = None # To store the result

        # Configure the grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)

        # QR import buttons
        self.import_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.import_frame.grid(row=0, column=0, columnspan=2, padx=20, pady=(20,0), sticky="ew")
        self.import_frame.grid_columnconfigure((0,1), weight=1)
        self.scan_screen_button = ctk.CTkButton(self.import_frame, text="Scan QR Code on Screen", command=self._scan_screen)
        self.scan_screen_button.grid(row=0, column=0, padx=(0,5), sticky="ew")
        self.open_image_button = ctk.CTkButton(self.import_frame, text="Open QR Code Image...", command=self._open_image)
        self.open_image_button.grid(row=0, column=1, padx=(5,0), sticky="ew")
        self.import_hint_label = ctk.CTkLabel(self, text="Or paste an otpauth:// link into the Secret Key field.", text_color="gray")
        self.import_hint_label.grid(row=1, column=0, columnspan=2, padx=20, pady=(2,0), sticky="w")

        # Widgets
        self.issuer_label = ctk.CTkLabel(self, text="Issuer Name:")
        self.issuer_label.grid(row=2, column=0, padx=(20,5), pady=(10,10), sticky="w")
        self.issuer_entry = ctk.CTkEntry(self, placeholder_text="e.g., Google, GitHub")
        self.issuer_entry.grid(row=2, column=1, padx=(5,20), pady=(10,10), sticky="ew")

        self.account_label = ctk.CTkLabel(self, text="Account Name:")
        self.account_label.grid(row=3, column=0, padx=(20,5), pady=10, sticky="w")
        self.account_entry = ctk.CTkEntry(self, placeholder_text="e.g., user@example.com, username")
        self.account_entry.grid(row=3, column=1, padx=(5,20), pady=10, sticky="ew")

        self.secret_label = ctk.CTkLabel(self, text="Secret Key:")
        self.secret_label.grid(row=4, column=0, padx=(20,5), pady=10, sticky="w")
        self.secret_entry = ctk.CTkEntry(self, placeholder_text="Enter Secret Key", width=300, font=ctk.CTkFont(size=14))
        self.secret_entry.grid(row=4, column=1, padx=(5,20), pady=10, sticky="ew")
        # Detect a pasted otpauth:// link
        self.secret_entry.bind("<KeyRelease>", self._check_for_otpauth_link)
        self.secret_entry.bind("<FocusOut>", self._check_for_otpauth_link)

        self.recovery_codes_label = ctk.CTkLabel(self, text="Recovery Codes (Optional):", font=ctk.CTkFont(size=14))
        self.recovery_codes_label.grid(row=5, column=0, padx=20, pady=(10, 0), sticky="w")
        self.recovery_codes_entry = ctk.CTkTextbox(self, width=300, height=80, font=ctk.CTkFont(size=14), wrap="word")
        self.recovery_codes_entry.grid(row=5, column=1, padx=(5,20), pady=5, sticky="ew")

        # Code options. Most services use the defaults; QR codes and otpauth:// links fill these in.
        self.options_label = ctk.CTkLabel(self, text="Code Options:")
        self.options_label.grid(row=6, column=0, padx=(20,5), pady=10, sticky="w")
        self.options_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.options_frame.grid(row=6, column=1, padx=(5,20), pady=10, sticky="w")
        self.digits_menu = ctk.CTkOptionMenu(self.options_frame, values=[f"{d} digits" for d in otp.DIGIT_OPTIONS], width=95)
        self.digits_menu.grid(row=0, column=0, padx=(0,5))
        self.period_menu = ctk.CTkOptionMenu(self.options_frame, values=["30 sec", "60 sec"], width=85)
        self.period_menu.grid(row=0, column=1, padx=5)
        self.algorithm_menu = ctk.CTkOptionMenu(self.options_frame, values=list(otp.ALGORITHMS), width=95)
        self.algorithm_menu.grid(row=0, column=2, padx=(5,0))
        self._set_code_options(otp.DEFAULT_DIGITS, otp.DEFAULT_PERIOD, otp.DEFAULT_ALGORITHM)

        if self.is_edit_mode and existing_data:
            self.issuer_entry.insert(0, existing_data.get("issuer_name", ""))
            self.account_entry.insert(0, existing_data.get("account_name", ""))
            self.secret_entry.insert(0, existing_data.get("secret_key", ""))
            self.recovery_codes_entry.insert("1.0", existing_data.get("recovery_codes", ""))
            self._set_code_options(existing_data.get("digits", otp.DEFAULT_DIGITS),
                                   existing_data.get("period", otp.DEFAULT_PERIOD),
                                   existing_data.get("algorithm", otp.DEFAULT_ALGORITHM))

        self.error_label_text = ctk.StringVar()
        self.error_label = ctk.CTkLabel(self, textvariable=self.error_label_text, text_color="red", wraplength=420)
        self.error_label.grid(row=7, column=0, columnspan=2, padx=20, pady=(0,5), sticky="ew")

        # Buttons Frame
        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.grid(row=8, column=0, columnspan=2, padx=20, pady=(10,20), sticky="e")
        self.buttons_frame.grid_columnconfigure((0,1), weight=0)

        self.ok_button = ctk.CTkButton(self.buttons_frame, text="OK", command=self._ok_event, width=100)
        self.ok_button.grid(row=0, column=1, padx=(10,0))

        self.cancel_button = ctk.CTkButton(self.buttons_frame, text="Cancel", command=self._cancel_event, width=100, fg_color="gray", hover_color="darkgray")
        self.cancel_button.grid(row=0, column=0, padx=0)

        self.issuer_entry.after(100, self.issuer_entry.focus_force)
        self.after(50, self._center_window)
        self.protocol("WM_DELETE_WINDOW", self._cancel_event)

    def _center_window(self):
        self.update_idletasks()
        if self.master and self.master.winfo_exists():
            master_x = self.master.winfo_x()
            master_y = self.master.winfo_y()
            master_width = self.master.winfo_width()
            master_height = self.master.winfo_height()
            dialog_width = self.winfo_width()
            dialog_height = self.winfo_height()
            x = master_x + (master_width - dialog_width) // 2
            y = master_y + (master_height - dialog_height) // 2
            x = max(0, x)
            y = max(0, y)
            self.geometry(f"+{x}+{y}")
        else:
            self.tk.eval(f'tk::PlaceWindow {self} center')

    def _set_code_options(self, digits: int, period: int, algorithm: str):
        self.digits_menu.set(f"{digits} digits")
        self.period_menu.set(f"{period} sec")
        self.algorithm_menu.set(algorithm)

    def _get_code_options(self) -> tuple[int, int, str]:
        digits = int(self.digits_menu.get().split()[0])
        period = int(self.period_menu.get().split()[0])
        return digits, period, self.algorithm_menu.get()

    def _fill_from_otpauth(self, uri: str) -> bool:
        """Fills the form from an otpauth:// link. Shows an error and returns False if it's invalid."""
        try:
            token = otp.parse_otpauth_uri(uri)
        except ValueError as e:
            self.error_label_text.set(str(e))
            return False

        for entry, value in ((self.issuer_entry, token["issuer_name"]), (self.account_entry, token["account_name"])):
            if value:
                entry.delete(0, ctk.END)
                entry.insert(0, value)
        self.secret_entry.delete(0, ctk.END)
        self.secret_entry.insert(0, token["secret_key"])
        self._set_code_options(token["digits"], token["period"], token["algorithm"])

        if not token["issuer_name"]:
            self.error_label_text.set("2FA details filled in. Please enter an Issuer Name.")
            self.issuer_entry.focus()
        else:
            self.error_label_text.set("")
            self.ok_button.focus()
        return True

    def _check_for_otpauth_link(self, event=None):
        if self.secret_entry.get().strip().lower().startswith("otpauth"):
            self._fill_from_otpauth(self.secret_entry.get())

    def _fill_from_image(self, image: Image.Image):
        try:
            from core.qr import decode_qr_codes
            codes = decode_qr_codes(image)
        except ImportError:
            self.error_label_text.set("QR scanning needs OpenCV. Run: pip install -r requirements.txt")
            return
        links = [code for code in codes if code.strip().lower().startswith("otpauth")]
        if not links:
            self.error_label_text.set("No 2FA QR code found. Make sure the whole QR code is visible.")
            return
        self._fill_from_otpauth(links[0])

    def _scan_screen(self):
        # Hide the app so it doesn't cover the QR code, then capture all screens
        self.withdraw()
        self.master.withdraw()
        self.after(SCREEN_CAPTURE_DELAY_MS, self._capture_screen)

    def _capture_screen(self):
        try:
            screenshot = ImageGrab.grab(all_screens=True)
        except Exception as e:
            screenshot = None
            self.error_label_text.set(f"Could not capture the screen: {e}")
        finally:
            self.master.deiconify()
            self.deiconify()
            self.lift()
            self.grab_set()
        if screenshot is not None:
            self._fill_from_image(screenshot)

    def _open_image(self):
        path = ctk.filedialog.askopenfilename(
            parent=self,
            title="Open QR Code Image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.webp"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with Image.open(path) as image:
                self._fill_from_image(image)
        except OSError as e:
            self.error_label_text.set(f"Could not open the image: {e}")

    def _ok_event(self, event=None):
        issuer = self.issuer_entry.get().strip()
        account = self.account_entry.get().strip()
        secret = self.secret_entry.get().strip()
        recovery_codes = self.recovery_codes_entry.get("1.0", "end-1c").strip()

        if secret.lower().startswith("otpauth"):
            # A link pasted without a key release or focus change (e.g. right before clicking OK)
            self._fill_from_otpauth(secret)
            return

        if not issuer:
            self.error_label_text.set("Issuer Name cannot be empty.")
            self.issuer_entry.focus()
            return
        if not account:
            self.error_label_text.set("Account Name cannot be empty.")
            self.account_entry.focus()
            return
        if not secret:
            self.error_label_text.set("Secret Key cannot be empty.")
            self.secret_entry.focus()
            return

        try:
            secret = normalize_secret_key(secret)
        except ValueError as e:
            self.error_label_text.set(str(e))
            self.secret_entry.focus()
            return

        digits, period, algorithm = self._get_code_options()
        self._user_input = {"issuer_name": issuer, "account_name": account, "secret_key": secret, "recovery_codes": recovery_codes,
                            "digits": digits, "period": period, "algorithm": algorithm}
        self.grab_release()
        self.destroy()

    def _cancel_event(self, event=None):
        self._user_input = None
        self.grab_release()
        self.destroy()

    def get_input(self):
        self.master.wait_window(self)
        return self._user_input
