# 2FA App

A secure and modern two-factor authentication (2FA) desktop application built with Python and CustomTkinter. Your TOTP secrets are encrypted with your PIN or password and stored in your system's keyring.

## Features

*   **Modern UI:** Built with CustomTkinter, supporting Light, Dark, and System modes.
*   **Encrypted Storage:** 2FA secrets and recovery codes are encrypted with a key that only your PIN or password can unlock, then stored in your system's native keyring.
*   **PIN or Password:** Choose a password (8+ characters, recommended) or a numeric PIN (6+ digits) to protect the app.
*   **QR Code Import:** Add tokens by scanning a QR code on your screen, opening a QR code image, or pasting an `otpauth://` link.
*   **Token Management:** Add, edit, and delete TOTP tokens, including 6, 7, or 8 digit codes, 30 or 60 second periods, and SHA1, SHA256, or SHA512.
*   **Recovery Code Storage:** Optionally save recovery codes alongside your tokens for easy access.
*   **Search:** Quickly find tokens by issuer or account name.
*   **Auto-Lock:** Automatically locks after a configurable period of inactivity.
*   **Clipboard Integration:** Copy TOTP codes; the clipboard clears after 30 seconds, or right away when the app locks or closes.
*   **Encrypted Backup & Restore:** Export/Import tokens to/from a password-protected, AES-GCM encrypted JSON file. Restoring skips tokens that are already in the app.

## Security

*   **Token Encryption:** Each token is encrypted with AES-256-GCM using a random data key. The data key is itself encrypted with a key derived from your PIN or password using scrypt (N=2^17, r=8, p=1, the OWASP recommendation), so tokens can't be read without it. Changing your PIN or password also moves every token to a new data key, so an old copy of your data plus your old PIN or password can't read them.
*   **System Keyring:** The encrypted tokens and encrypted data key are stored in your OS's credential manager. Keyring entries use random IDs, so they don't reveal which services you use.
*   **Backup Encryption:** Backups are encrypted using AES-256-GCM with a key derived from a separate backup password using PBKDF2-SHA256 with 600,000 iterations (`cryptography` library). Backups made by older versions can still be restored.
*   **Wrong-Attempt Lockout:** After 3 wrong PIN or password attempts in a row, the app makes you wait 30 seconds, doubling with each further wrong attempt up to 15 minutes. The count is kept in the keyring, so restarting the app doesn't reset it.
*   **Auto-Lock:** Locking hides the main window, closes any open dialogs, and discards the decryption key and decrypted tokens until you unlock it again. (Python can't guarantee discarded data is wiped from memory immediately.)
*   **Clipboard Timeout:** Auto-clears copied codes. Note that Windows clipboard history (Win+V), if enabled, keeps its own copy.

### Choosing a PIN or password

Anyone who copies your encrypted data can try to guess your PIN or password on their own computer, where the app's lockout doesn't apply. A 6-digit PIN has only a million possibilities, which a typical PC can try in about a day; a good password would take far longer. Use a password if you can.

### What encryption doesn't protect against

Malware that records your keystrokes, or that reads the app's memory while it's unlocked, can still get your secrets. Keep your OS account and computer secure, and consider storing recovery codes somewhere separate from the device that holds your 2FA secrets.

### If you forget your PIN or password

Your tokens can't be decrypted without it, and there is no recovery option. Keep an up-to-date encrypted backup (Settings > Backup Tokens) with a backup password you won't forget.

## Requirements

*   Python 3.10+
*   A functioning `keyring` backend for your OS (see Setup).
*   Libraries in `requirements.txt`, including `cryptography` for encryption and `opencv-python` for QR code scanning.

## Setup and Installation

1.  **Clone Repository:**
    ```bash
    git clone https://github.com/MRFrazer25/2FA_App.git
    cd 2FA_App
    ```

2.  **Install Dependencies (Virtual Environment Recommended):**
    ```bash
    python -m venv venv
    # Activate the virtual environment:
    # Windows: .\venv\Scripts\activate
    # macOS/Linux (bash/zsh): source venv/bin/activate
    # (For other shells, consult the Python venv documentation)
    pip install -r requirements.txt
    ```

3.  **Ensure Keyring Backend:**
    *   **Windows/macOS:** Works out-of-the-box; `keyring` installs what it needs.
    *   **Linux:** Requires a DBus-based password manager (e.g., GNOME Keyring). You might need to install packages like `python3-secretstorage python3-dbus python3-gi`. `pip install secretstorage jeepney` may also be required depending on your setup.
    Refer to [Python Keyring documentation](https://keyring.readthedocs.io/) for detailed OS-specific setup.

## Running the Application

```bash
python main.py
```
On first launch, you'll choose a PIN or password. Navigate settings to manage auto-lock, change your PIN or password, or backup/restore your tokens.

**Upgrading from an older version:** enter your existing PIN as usual. Your tokens are then encrypted automatically. If your PIN is shorter than the new minimum, you'll be asked to choose a new PIN or password first. Backups made after upgrading can't be restored by older versions.

**Adding a token:** click **Add Token**, then either click **Scan QR Code on Screen** while the service's QR code is visible, open a saved QR code image, paste an `otpauth://` link into the Secret Key field, or type the details in yourself.

## Running Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```
The tests use an in-memory keyring, so they never touch your real credential store.

## Troubleshooting

*   **Keyring Errors:** Ensure your OS backend is set up (see Setup & Keyring docs). If you see "Keyring backend not found", you need to install the appropriate backend for your OS.
*   **QR Scanning:** Screenshots taken for scanning are only processed in memory and never saved. Make sure the whole QR code is visible and not covered by another window. On macOS, allow Screen Recording for your terminal or Python in System Settings > Privacy & Security. If scanning says OpenCV is missing, run `pip install -r requirements.txt` again.
*   **Icon Issues:** Ensure `assets/` directory is in the project root with all `.png` icons.

## License

MIT License - see the [LICENSE](LICENSE) file.

## Disclaimer
This application is provided as-is. While efforts have been made to make it secure, you are responsible for maintaining the security of your system, your PIN or password, and your backup passwords.
