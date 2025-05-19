# 2FA App

A secure and modern two-factor authentication (2FA) desktop application built with Python and CustomTkinter. It uses your system's keyring for secure storage of TOTP secrets and application settings.

## Features

*   **Modern UI:** Built with CustomTkinter, supporting Light, Dark, and System modes.
*   **Secure Storage:** 2FA secrets, recovery codes, and app PIN stored in your system's native keyring.
*   **PIN Protection:** Application access safeguarded by a user-defined PIN (hashed using PBKDF2-SHA256).
*   **Token Management:** Manually add, edit, and delete TOTP tokens.
*   **Recovery Code Storage:** Optionally save recovery codes alongside your tokens for easy access.
*   **Search:** Quickly find tokens by issuer or account name.
*   **Auto-Lock:** Automatically locks after a configurable period of inactivity.
*   **Clipboard Integration:** Copy TOTP codes; clipboard clears after 30 seconds.
*   **Encrypted Backup & Restore:** Export/Import tokens to/from a password-protected, AES-GCM encrypted JSON file.

## Security

*   **System Keyring:** Leverages your OS's credential manager for sensitive data (token secrets, PIN hash, settings).
*   **PIN Hashing:** Uses PBKDF2-SHA256 with a unique salt and high iteration count (`hashlib`).
*   **Backup Encryption:** Backups are encrypted using AES-256-GCM with a key derived from a user-provided password using PBKDF2-SHA256 (`cryptography` library).
*   **Clipboard Timeout:** Auto-clears copied codes.

## Requirements

*   Python 3.7+
*   A functioning `keyring` backend for your OS (see Setup).
*   Libraries in `requirements.txt` (install via `pip install -r requirements.txt`), which includes `cryptography` for encrypted backups.

## Setup and Installation

1.  **Clone Repository:**
    ```bash
    git clone https://github.com/MRFrazer25/2FA_App.git
    cd 2FA_App
    ```

2.  **Install Dependencies (Virtual Environment Recommended):
    ```bash
    python -m venv venv
    # Activate the virtual environment:
    # Windows: .\venv\Scripts\activate
    # macOS/Linux (bash/zsh): source venv/bin/activate
    # (For other shells, consult the Python venv documentation)
    pip install -r requirements.txt
    ```

3.  **Ensure Keyring Backend:**
    *   **Windows/macOS:** Usually works out-of-the-box. (If issues on Windows, `pip install keyring-pywin32-ctypes` might be needed if not automatically picked up).
    *   **Linux:** Requires a DBus-based password manager (e.g., GNOME Keyring). You might need to install packages like `python3-secretstorage python3-dbus python3-gi`. `pip install secretstorage jeepney` may also be required depending on your setup.
    Refer to [Python Keyring documentation](https://keyring.readthedocs.io/) for detailed OS-specific setup.

## Running the Application

```bash
python main.py
```
On first launch, you'll set an application PIN. Navigate settings to manage auto-lock, change PIN, or backup/restore your tokens.

## Troubleshooting

*   **Keyring Errors:** Ensure your OS backend is set up (see Setup & Keyring docs). If you see "Keyring backend not found", you need to install the appropriate backend for your OS.
*   **Icon Issues:** Ensure `assets/` directory is in the project root with all `.png` icons.

## License

MIT License - see the [LICENSE](LICENSE) file.

## Disclaimer
This application is provided as-is. While efforts have been made to make it secure, you are responsible for maintaining the security of your system, your application PIN, and your backup passwords. 