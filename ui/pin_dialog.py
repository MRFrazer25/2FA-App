import customtkinter as ctk

class PinDialog(ctk.CTkToplevel):
    """Modal dialog for entering and confirming a PIN."""
    def __init__(self, master, title="Enter PIN", prompt="Please enter your application PIN:", 
                 confirm_pin_mode=False, show_cancel=True):
        super().__init__(master)
        self.lift()
        self.attributes("-topmost", True) 
        self.grab_set()
        self.resizable(False, False)
        self.title(title)

        self._user_pin = None
        self._confirm_pin_mode = confirm_pin_mode
        self._show_cancel = show_cancel # Store for later use in WM_DELETE_WINDOW

        # Widgets
        self.prompt_label = ctk.CTkLabel(self, text=prompt, wraplength=300, justify="center") 
        self.prompt_label.pack(padx=20, pady=(20,10))

        self.pin_entry = ctk.CTkEntry(self, placeholder_text="Enter PIN", show="*", width=200, font=ctk.CTkFont(size=16))
        self.pin_entry.pack(padx=20, pady=5)

        if self._confirm_pin_mode:
            self.confirm_pin_entry = ctk.CTkEntry(self, placeholder_text="Confirm PIN", show="*", width=200, font=ctk.CTkFont(size=16))
            self.confirm_pin_entry.pack(padx=20, pady=(5,10))
        else:
            self.confirm_pin_entry = None # Ensure it exists as None for logic in _ok_event and _handle_close_button

        self.error_label_text = ctk.StringVar()
        self.error_label = ctk.CTkLabel(self, textvariable=self.error_label_text, text_color="red")
        self.error_label.pack(padx=20, pady=(0,5))

        # Buttons Frame
        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.pack(padx=20, pady=(10,20), fill="x")
        
        if self._show_cancel:
            self.buttons_frame.grid_columnconfigure(0, weight=1)
            self.buttons_frame.grid_columnconfigure(1, weight=1)
            self.cancel_button = ctk.CTkButton(self.buttons_frame, text="Cancel", command=self._cancel_event, width=100, fg_color="gray", hover_color="darkgray")
            self.cancel_button.grid(row=0, column=0, padx=(0,5), sticky="ew")
            self.ok_button = ctk.CTkButton(self.buttons_frame, text="OK", command=self._ok_event, width=100)
            self.ok_button.grid(row=0, column=1, padx=(5,0), sticky="ew")
        else:
            self.buttons_frame.grid_columnconfigure(0, weight=1)
            self.ok_button = ctk.CTkButton(self.buttons_frame, text="OK", command=self._ok_event, width=100)
            self.ok_button.grid(row=0, column=0, sticky="ew")

        self.pin_entry.after(100, self.pin_entry.focus_force)
        # Bind Return key to OK event for convenience
        self.bind("<Return>", self._ok_event)
        self.pin_entry.bind("<Return>", self._ok_event) # Specifically for pin_entry
        if self._confirm_pin_mode and self.confirm_pin_entry:
             self.confirm_pin_entry.bind("<Return>", self._ok_event)

        self.protocol("WM_DELETE_WINDOW", self._handle_close_button) 
        self.after(50, self._center_window)
        # Release topmost after a delay, relying more on grab_set for modality
        self.after(150, lambda: self.attributes("-topmost", False)) 

    def _handle_close_button(self):
        if self._show_cancel:
            self._cancel_event()
        else:
            # This is for mandatory PIN dialogs (initial setup, app unlock)
            # Closing this window is treated as a cancellation/failure leading to app exit.
            self._user_pin = None # Ensure pin is None to signal failure to caller
            # The master application is responsible for exiting if pin is None in this context.
            # Call the master's quit function directly if it exists.
            if hasattr(self.master, 'quit_application_if_pin_cancelled') and callable(getattr(self.master, 'quit_application_if_pin_cancelled')):
                 self.master.quit_application_if_pin_cancelled()
            # Even if master handles quit, ensure dialog is cleaned up.
            self.grab_release() 
            self.destroy()


    def _center_window(self):
        self.update_idletasks() # Ensure window dimensions are calculated
        if self.master and self.master.winfo_exists():
            master_x = self.master.winfo_x()
            master_y = self.master.winfo_y()
            master_width = self.master.winfo_width()
            master_height = self.master.winfo_height()
            
            self.update_idletasks() # Ensure dialog dimensions are up-to-date
            dialog_width = self.winfo_width()
            dialog_height = self.winfo_height()

            # Check for valid dialog dimensions, retry if not ready
            if dialog_width <= 1 or dialog_height <= 1: 
                self.after(20, self._center_window) # Retry shortly
                return

            x = master_x + (master_width - dialog_width) // 2
            y = master_y + (master_height - dialog_height) // 2
            x = max(0,x) # ensure it's not off-screen
            y = max(0,y)
            self.geometry(f"+{x}+{y}") # Position relative to top-left of screen
        else:
            # Fallback if no master, center on screen
            self.eval(f'tk::PlaceWindow {str(self)} center')

    def _ok_event(self, event=None):
        pin1 = self.pin_entry.get()
        if not pin1:
            self.error_label_text.set("PIN cannot be empty.")
            self.pin_entry.focus()
            return
        
        if len(pin1) < 4 : # Consistent with app_lock.py min length
            self.error_label_text.set("PIN must be at least 4 characters.")
            self.pin_entry.focus()
            return

        if self._confirm_pin_mode:
            if not self.confirm_pin_entry: # Should ideally not be None if _confirm_pin_mode is True
                 self.error_label_text.set("Internal error: Confirmation PIN entry missing.")
                 return
            pin2 = self.confirm_pin_entry.get()
            if not pin2:
                self.error_label_text.set("Please confirm your PIN.")
                self.confirm_pin_entry.focus()
                return
            if pin1 != pin2:
                self.error_label_text.set("PINs do not match.")
                self.confirm_pin_entry.focus()
                self.confirm_pin_entry.delete(0, ctk.END) # Clear confirmation field on mismatch
                return
        
        self._user_pin = pin1
        self.grab_release()
        self.destroy()

    def _cancel_event(self, event=None):
        self._user_pin = None
        # For a cancellable dialog, just close it. 
        # The caller (e.g., main_app) will check get_pin() and decide what to do if it's None.
        # Mandatory dialogs (show_cancel=False) handle exit via _handle_close_button.
        self.grab_release()
        self.destroy()
            
    def get_pin(self):
        self.master.wait_window(self)
        return self._user_pin