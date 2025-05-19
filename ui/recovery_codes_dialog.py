import customtkinter as ctk

class RecoveryCodesDialog(ctk.CTkToplevel):
    """Modal dialog to display recovery codes for viewing and copying."""
    def __init__(self, master, title: str, recovery_codes: str):
        super().__init__(master)

        self.title(title)
        self.lift()  # Lift window on top
        self.attributes("-topmost", True)  # Keep on top
        self.grab_set()  # Make modal
        self.resizable(False, False)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        container_frame = ctk.CTkFrame(self)
        container_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        container_frame.grid_columnconfigure(0, weight=1)
        container_frame.grid_rowconfigure(0, weight=0) # For label
        container_frame.grid_rowconfigure(1, weight=1) # For textbox
        container_frame.grid_rowconfigure(2, weight=0) # For button

        info_label = ctk.CTkLabel(container_frame, text="You can select and copy the codes below (Ctrl+C or right-click).")
        info_label.grid(row=0, column=0, padx=10, pady=(0,10), sticky="w")

        self.codes_textbox = ctk.CTkTextbox(container_frame, wrap="word", height=150, width=350, font=ctk.CTkFont(size=14))
        self.codes_textbox.insert("1.0", recovery_codes)
        self.codes_textbox.configure(state="disabled")
        self.codes_textbox.grid(row=1, column=0, padx=10, pady=0, sticky="nsew")
        self.ok_button = ctk.CTkButton(container_frame, text="Close", command=self.destroy, width=100)
        self.ok_button.grid(row=2, column=0, padx=10, pady=(15,0), sticky="e")

        self.after(50, self._center_window)
        self.protocol("WM_DELETE_WINDOW", self.destroy) # Ensure clicking X closes it

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
            # Fallback if master isn't available or valid, though it should be.
            self.eval(f'tk::PlaceWindow {str(self)} center')

    def show(self):
        self.master.wait_window(self) 