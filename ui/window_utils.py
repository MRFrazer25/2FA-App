def center_window(window):
    """Centers a dialog over its master's window, or on the screen if that window is hidden
    (at startup or while locked). Uses the master's top-level window and screen coordinates,
    since a master inside the window (e.g. the token list) has coordinates relative to its parent."""
    window.update_idletasks() # Ensure window dimensions are calculated
    dialog_width = window.winfo_width()
    dialog_height = window.winfo_height()
    if dialog_width <= 1 or dialog_height <= 1:
        window.after(20, lambda: center_window(window)) # Not laid out yet, retry shortly
        return

    owner = window.master.winfo_toplevel() if window.master else None
    if owner is not None and owner.winfo_exists() and owner.winfo_viewable():
        x = owner.winfo_rootx() + (owner.winfo_width() - dialog_width) // 2
        y = owner.winfo_rooty() + (owner.winfo_height() - dialog_height) // 2
        window.geometry(f"+{max(0, x)}+{max(0, y)}")
    else:
        window.tk.eval(f'tk::PlaceWindow {window} center')
