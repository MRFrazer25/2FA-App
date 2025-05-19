import customtkinter as ctk
from PIL import Image # For loading icons
import os # For path joining

class SidebarFrame(ctk.CTkFrame):
    """A frame for the application sidebar, containing navigation buttons and appearance settings."""
    def __init__(self, master, add_token_callback, show_settings_callback, show_home_callback, lock_app_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.add_token_callback = add_token_callback
        self.show_settings_callback = show_settings_callback
        self.show_home_callback = show_home_callback
        self.lock_app_callback = lock_app_callback

        # Load Icons
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_script_dir)
        assets_path = os.path.join(project_root, "assets")

        self.home_icon = self._load_icon(os.path.join(assets_path, "home_icon.png"))
        self.add_token_icon = self._load_icon(os.path.join(assets_path, "plus_circle_icon.png"))
        self.settings_icon = self._load_icon(os.path.join(assets_path, "settings_icon.png"))
        self.lock_icon = self._load_icon(os.path.join(assets_path, "lock_icon.png"))

        # Configure grid layout
        self.grid_rowconfigure((0, 1, 2, 3, 4), weight=0) # Buttons
        self.grid_rowconfigure(5, weight=1) # Spacer

        self.logo_label = ctk.CTkLabel(self, text="2FA App", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 15))

        self.home_button = ctk.CTkButton(self, image=self.home_icon, text="All Tokens", 
                                           compound="left", anchor="w", command=self.show_home_callback,
                                           font=ctk.CTkFont(size=14))
        self.home_button.grid(row=1, column=0, padx=20, pady=7, sticky="ew")

        self.add_token_button = ctk.CTkButton(self, image=self.add_token_icon, text="Add Token", 
                                                compound="left", anchor="w", command=self.add_token_callback,
                                                font=ctk.CTkFont(size=14))
        self.add_token_button.grid(row=2, column=0, padx=20, pady=7, sticky="ew")

        self.lock_app_button = ctk.CTkButton(self, image=self.lock_icon, text="Lock App",
                                             compound="left", anchor="w", command=self.lock_app_callback,
                                             font=ctk.CTkFont(size=14), fg_color="#505050", hover_color="#606060")
        self.lock_app_button.grid(row=3, column=0, padx=20, pady=7, sticky="ew")

        self.settings_button = ctk.CTkButton(self, image=self.settings_icon, text="Settings", 
                                             compound="left", anchor="w", command=self.show_settings_callback,
                                             font=ctk.CTkFont(size=14))
        self.settings_button.grid(row=4, column=0, padx=20, pady=7, sticky="ew")

        # Appearance Mode Toggle
        self.appearance_mode_label = ctk.CTkLabel(self, text="Appearance:", anchor="w", font=ctk.CTkFont(size=12))
        self.appearance_mode_label.grid(row=6, column=0, padx=20, pady=(15, 2), sticky="sw")
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self, values=["Light", "Dark", "System"],
                                                               command=self.change_appearance_mode_event, 
                                                               font=ctk.CTkFont(size=12), width=180)
        self.appearance_mode_optionemenu.grid(row=7, column=0, padx=20, pady=(0,20), sticky="sew")
        self.appearance_mode_optionemenu.set("System")

    def _load_icon(self, path, size=(20,20)):
        """Loads an icon, returning a CTkImage or None if path is invalid."""
        try:
            return ctk.CTkImage(Image.open(path), size=size)
        except FileNotFoundError:
            print(f"Warning: Icon not found at {path}. A placeholder will be used.")
            placeholder = Image.new('RGBA', size, (0,0,0,0)) # Transparent placeholder
            return ctk.CTkImage(placeholder, size=size)
        except Exception as e:
            print(f"Warning: Error loading icon {path}: {e}. A placeholder will be used.")
            placeholder = Image.new('RGBA', size, (0,0,0,0)) # Transparent placeholder
            return ctk.CTkImage(placeholder, size=size)

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)