import customtkinter as ctk

class PasswordDialog(ctk.CTkToplevel):
    """Modal dialog for entering a backup password.
    With confirm=True (setting a new password), the password must be entered twice and be at least 8 characters."""
    def __init__(self, master, title="Set Backup Password", 
                 prompt="Please enter a password for your backup:",
                 confirm_prompt="Confirm Password:",
                 confirm=True):
        super().__init__(master)
        self.lift()
        self.attributes("-topmost", True)
        self.grab_set()
        self.resizable(False, False)
        self.title(title)

        self._user_password = None
        self._confirm = confirm

        # Widgets
        self.prompt_label = ctk.CTkLabel(self, text=prompt, wraplength=300, justify="center")
        self.prompt_label.pack(padx=20, pady=(20, 10))

        self.password_entry = ctk.CTkEntry(self, placeholder_text="Enter Password", show="*", width=250, font=ctk.CTkFont(size=14))
        self.password_entry.pack(padx=20, pady=5)

        if self._confirm:
            self.confirm_prompt_label = ctk.CTkLabel(self, text=confirm_prompt, wraplength=300, justify="center")
            self.confirm_prompt_label.pack(padx=20, pady=(10,0))

            self.confirm_password_entry = ctk.CTkEntry(self, placeholder_text="Confirm Password", show="*", width=250, font=ctk.CTkFont(size=14))
            self.confirm_password_entry.pack(padx=20, pady=(5,10))

        self.error_label_text = ctk.StringVar()
        self.error_label = ctk.CTkLabel(self, textvariable=self.error_label_text, text_color="red")
        self.error_label.pack(padx=20, pady=(0, 5))

        # Buttons Frame
        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.pack(padx=20, pady=(10, 20), fill="x")

        self.buttons_frame.grid_columnconfigure(0, weight=1)
        self.buttons_frame.grid_columnconfigure(1, weight=1)
        self.cancel_button = ctk.CTkButton(self.buttons_frame, text="Cancel", command=self._cancel_event, width=100, fg_color="gray", hover_color="darkgray")
        self.cancel_button.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        self.ok_button = ctk.CTkButton(self.buttons_frame, text="OK", command=self._ok_event, width=100)
        self.ok_button.grid(row=0, column=1, padx=(5, 0), sticky="ew")

        self.password_entry.after(100, self.password_entry.focus_force)
        # Bind Return key to OK event (applies to the entry fields too)
        self.bind("<Return>", self._ok_event)

        self.protocol("WM_DELETE_WINDOW", self._cancel_event)
        self.after(50, self._center_window)
        self.after(150, lambda: self.attributes("-topmost", False))

    def _center_window(self):
        self.update_idletasks()
        if self.master and self.master.winfo_exists():
            master_x = self.master.winfo_x()
            master_y = self.master.winfo_y()
            master_width = self.master.winfo_width()
            master_height = self.master.winfo_height()
            
            self.update_idletasks()
            dialog_width = self.winfo_width()
            dialog_height = self.winfo_height()

            if dialog_width <= 1 or dialog_height <= 1:
                self.after(20, self._center_window)
                return

            x = master_x + (master_width - dialog_width) // 2
            y = master_y + (master_height - dialog_height) // 2
            x = max(0,x)
            y = max(0,y)
            self.geometry(f"+{x}+{y}")
        else:
            self.tk.eval(f'tk::PlaceWindow {self} center')

    def _ok_event(self, event=None):
        pass1 = self.password_entry.get()

        if not pass1:
            self.error_label_text.set("Password cannot be empty.")
            self.password_entry.focus()
            return

        if self._confirm:
            # Basic password strength requirement for new passwords
            if len(pass1) < 8:
                self.error_label_text.set("Password should be at least 8 characters.")
                self.password_entry.focus()
                return

            pass2 = self.confirm_password_entry.get()
            if not pass2:
                self.error_label_text.set("Please confirm your password.")
                self.confirm_password_entry.focus()
                return

            if pass1 != pass2:
                self.error_label_text.set("Passwords do not match.")
                self.confirm_password_entry.focus()
                self.confirm_password_entry.delete(0, ctk.END)
                return
        
        self._user_password = pass1
        self.grab_release()
        self.destroy()

    def _cancel_event(self, event=None):
        self._user_password = None
        self.grab_release()
        self.destroy()
            
    def get_password(self):
        self.master.wait_window(self)
        return self._user_password