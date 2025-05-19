import customtkinter as ctk

class AddTokenDialog(ctk.CTkToplevel):
    """Dialog for adding a new token or editing an existing one."""
    def __init__(self, master=None, existing_data: dict = None, current_type: str = "TOTP"):
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

        # Widgets
        self.issuer_label = ctk.CTkLabel(self, text="Issuer Name:")
        self.issuer_label.grid(row=0, column=0, padx=(20,5), pady=(20,10), sticky="w")
        self.issuer_entry = ctk.CTkEntry(self, placeholder_text="e.g., Google, GitHub")
        self.issuer_entry.grid(row=0, column=1, padx=(5,20), pady=(20,10), sticky="ew")

        self.account_label = ctk.CTkLabel(self, text="Account Name:")
        self.account_label.grid(row=1, column=0, padx=(20,5), pady=10, sticky="w")
        self.account_entry = ctk.CTkEntry(self, placeholder_text="e.g., user@example.com, username")
        self.account_entry.grid(row=1, column=1, padx=(5,20), pady=10, sticky="ew")

        self.secret_label = ctk.CTkLabel(self, text="Secret Key:")
        self.secret_label.grid(row=2, column=0, padx=(20,5), pady=10, sticky="w")
        self.secret_entry = ctk.CTkEntry(self, placeholder_text="Enter Secret Key", width=300, font=ctk.CTkFont(size=14))
        self.secret_entry.grid(row=2, column=1, padx=(5,20), pady=5)

        self.recovery_codes_label = ctk.CTkLabel(self, text="Recovery Codes (Optional):", font=ctk.CTkFont(size=14))
        self.recovery_codes_label.grid(row=3, column=0, padx=20, pady=(10, 0), sticky="w")
        self.recovery_codes_entry = ctk.CTkTextbox(self, width=300, height=80, font=ctk.CTkFont(size=14), wrap="word")
        self.recovery_codes_entry.grid(row=3, column=1, padx=20, pady=5, sticky="ew")

        if self.is_edit_mode and existing_data:
            self.issuer_entry.insert(0, existing_data.get("issuer_name", ""))
            self.account_entry.insert(0, existing_data.get("account_name", ""))
            self.secret_entry.insert(0, existing_data.get("secret_key", ""))
            self.recovery_codes_entry.insert("1.0", existing_data.get("recovery_codes", ""))

        self.error_label_text = ctk.StringVar()
        self.error_label = ctk.CTkLabel(self, textvariable=self.error_label_text, text_color="red")
        self.error_label.grid(row=4, column=0, columnspan=2, padx=20, pady=(0,5), sticky="ew")

        # Buttons Frame 
        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.grid(row=5, column=0, columnspan=2, padx=20, pady=(10,20), sticky="e") # Adjusted row to 4, increased pady
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
            self.eval(f'tk::PlaceWindow {str(self)} center')

    def _ok_event(self, event=None):
        issuer = self.issuer_entry.get().strip()
        account = self.account_entry.get().strip()
        secret = self.secret_entry.get().strip()
        recovery_codes = self.recovery_codes_entry.get("1.0", "end-1c").strip()

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
        
        # Basic Base32 validation for the secret key.
        allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" # Valid characters for a Base32 string (uppercase).
        temp_secret = secret.replace(" ", "").upper() # Remove spaces and convert to uppercase for consistent validation.
        is_valid_base32_chars = all(c in allowed_chars for c in temp_secret)
        
        # Common Base32 secret lengths are multiples of 8, often 16, 32.
        # Allowing lengths that are multiples of 4 covers common non-padded and padded forms.
        # A typical minimum length for OTP secrets is 16 characters (80 bits).
        if not (is_valid_base32_chars and len(temp_secret) >= 16 and (len(temp_secret) % 8 == 0 or (len(temp_secret) % 4 == 0 and len(temp_secret) > 16))):
            self.error_label_text.set("Invalid Secret Key (must be valid Base32, typically 16+ chars, e.g. JBSWY3DPEHPK3PXP).")
            self.secret_entry.focus()
            return

        self._user_input = {"issuer_name": issuer, "account_name": account, "secret_key": temp_secret, "recovery_codes": recovery_codes}
        self.grab_release()
        self.destroy()

    def _cancel_event(self, event=None):
        self._user_input = None
        self.grab_release()
        self.destroy()

    def get_input(self):
        self.master.wait_window(self)
        return self._user_input