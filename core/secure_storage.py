import keyring
import json

SERVICE_NAME = "2FA App"

# For storing the list of account identifiers
ACCOUNTS_LIST_KEY = "__accounts_list__"
AUTO_LOCK_SETTING_KEY = "__auto_lock_timeout_seconds__"
DEFAULT_AUTO_LOCK_SECONDS = 300 # 5 minutes

def save_token_secret(account_name: str, issuer_name: str, secret_key: str, token_type: str = "TOTP", identifier: str = None, recovery_codes: str = None) -> str | None:
    """Saves the token secret, type, and other details for a given account.
    If an identifier is provided, it attempts to update that existing token.
    Otherwise, a new token is created.

    Args:
        account_name: The name of the account (e.g., user's email or username).
        issuer_name: The name of the service or issuer (e.g., "Google", "GitHub").
        secret_key: The Base32 encoded secret key for OTP generation.
        token_type: The type of token, defaults to "TOTP".
        identifier: Optional. The existing identifier of the token to update.
                    If None, a new token is created and a new identifier generated.
        recovery_codes: Optional. The recovery codes for the token.

    Returns:
        The identifier (new or existing) of the saved token, or None on failure.
    """
    if not account_name or not secret_key or not issuer_name:
        raise ValueError("Account name, issuer name, and secret key cannot be empty.")
    
    # Validate token_type (basic validation)
    if token_type.upper() not in ["TOTP", "HOTP"]:
        raise ValueError(f"Unsupported token type: {token_type}. Must be TOTP or HOTP.")

    # Use provided identifier for updates, or generate a new one for new tokens.
    if identifier:
        current_identifier = identifier
    else:
        current_identifier = f"{issuer_name.lower().replace(' ', '_')}_{account_name.lower().replace(' ', '_')}"
        # Basic collision avoidance - if this exact ID exists, append a number
        temp_id = current_identifier
        count = 1
        # Check if the token secret exists for the generated identifier
        while get_token_secret(temp_id) is not None:
            temp_id = f"{current_identifier}_{count}"
            count += 1
        current_identifier = temp_id

    data = {
        "account_name": account_name,
        "issuer_name": issuer_name,
        "secret_key": secret_key,
        "type": token_type, # Store token_type
        "recovery_codes": recovery_codes # Store recovery codes
    }
    try:
        keyring.set_password(SERVICE_NAME, current_identifier, json.dumps(data))
        _add_account_to_list(current_identifier) # Ensure it's in the list
        return current_identifier
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Secure storage is unavailable.")
        raise
    except Exception as e:
        print(f"Error saving secret: {e}")
        raise

def get_token_secret(identifier: str) -> dict | None:
    """Retrieves the token data (account_name, issuer_name, secret_key, type, recovery_codes) for a given identifier."""
    try:
        secret_json = keyring.get_password(SERVICE_NAME, identifier)
        if secret_json:
            data = json.loads(secret_json)
            # Ensure essential keys are present, provide defaults for 'type' if missing
            return {
                "identifier": identifier,
                "account_name": data.get("account_name"),
                "issuer_name": data.get("issuer_name"),
                "secret_key": data.get("secret_key"),
                "type": data.get("type", "TOTP"), # Default to TOTP if type is missing
                "recovery_codes": data.get("recovery_codes", "") # Default to empty string
            }
        return None
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Secure storage is unavailable.")
        return None
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None

def delete_token_secret(identifier: str):
    """Deletes the token secret for a given identifier."""
    try:
        keyring.delete_password(SERVICE_NAME, identifier)
        _remove_account_from_list(identifier)
    except keyring.errors.NoKeyringError:
        pass # If keyring not found, can't delete anyway.
    except keyring.errors.PasswordDeleteError:
        _remove_account_from_list(identifier) # Attempt to remove from list even if direct delete fails
    except Exception as e:
        print(f"Error deleting secret: {e}")

def get_all_token_identifiers() -> list[str]:
    """Retrieves the list of all account identifiers stored."""
    try:
        accounts_json = keyring.get_password(SERVICE_NAME, ACCOUNTS_LIST_KEY)
        if accounts_json:
            return json.loads(accounts_json)
        return []
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Secure storage is unavailable.")
        return []
    except Exception as e:
        print(f"Error retrieving account list: {e}")
        return []

def _add_account_to_list(identifier: str):
    """Adds an account identifier to the centrally managed list."""
    accounts = get_all_token_identifiers()
    if identifier not in accounts:
        accounts.append(identifier)
        try:
            keyring.set_password(SERVICE_NAME, ACCOUNTS_LIST_KEY, json.dumps(accounts))
        except keyring.errors.NoKeyringError:
            # Already handled by get_all_token_identifiers, but good to be aware
            pass 

def _remove_account_from_list(identifier: str):
    """Removes an account identifier from the list."""
    accounts = get_all_token_identifiers()
    if identifier in accounts:
        accounts.remove(identifier)
        try:
            keyring.set_password(SERVICE_NAME, ACCOUNTS_LIST_KEY, json.dumps(accounts))
        except keyring.errors.NoKeyringError:
            pass

def save_auto_lock_setting(timeout_seconds: int):
    """Saves the auto-lock timeout in seconds."""
    try:
        keyring.set_password(SERVICE_NAME, AUTO_LOCK_SETTING_KEY, str(timeout_seconds))
    except keyring.errors.NoKeyringError:
        print("Keyring backend not found. Cannot save auto-lock setting.")
    except Exception as e:
        print(f"Error saving auto-lock setting: {e}")

def get_auto_lock_setting() -> int:
    """Retrieves the auto-lock timeout in seconds. Returns default if not set or error."""
    try:
        timeout_str = keyring.get_password(SERVICE_NAME, AUTO_LOCK_SETTING_KEY)
        if timeout_str is not None:
            return int(timeout_str)
    except keyring.errors.NoKeyringError:
        pass
    except Exception as e:
        print(f"Error retrieving auto-lock setting: {e}. Using default.")
    return DEFAULT_AUTO_LOCK_SECONDS # Default value

def get_all_token_data() -> list[dict]:
    """
    Retrieves all token data (identifier, account_name, issuer_name, secret_key, type) 
    for all stored accounts.
    Returns a list of dictionaries, where each dictionary represents a token.
    """
    all_data = []
    identifiers = get_all_token_identifiers()
    for identifier_from_list in identifiers:
        token_info = get_token_secret(identifier_from_list) # Use the identifier from the list
        if token_info:
            # Ensure get_token_secret now returns a dict with 'identifier' and 'type'
            # The structure here assumes get_token_secret returns all necessary fields.
            if token_info.get("account_name") and token_info.get("secret_key") and token_info.get("issuer_name"):
                 all_data.append(token_info) # Append the whole dict returned by get_token_secret
            else:
                print(f"[secure_storage] Warning: Skipping token for identifier '{identifier_from_list}' during list retrieval due to missing critical data. Account: '{token_info.get('account_name')}', Issuer: '{token_info.get('issuer_name')}'")
    return all_data