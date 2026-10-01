import hashlib
import pyotp
from urllib.parse import urlparse, parse_qs, unquote

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_ALGORITHM = "SHA1"

DIGIT_OPTIONS = (6, 7, 8)
MIN_PERIOD = 10
MAX_PERIOD = 300
ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

def validate_settings(digits: int, period: int, algorithm: str):
    """Raises ValueError if the code length, period, or algorithm isn't supported."""
    if digits not in DIGIT_OPTIONS:
        raise ValueError(f"Code length must be {', '.join(map(str, DIGIT_OPTIONS))} digits.")
    if not isinstance(period, int) or not MIN_PERIOD <= period <= MAX_PERIOD:
        raise ValueError(f"Code period must be between {MIN_PERIOD} and {MAX_PERIOD} seconds.")
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Algorithm must be one of {', '.join(ALGORITHMS)}.")

def make_totp(secret_key: str, digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
              algorithm: str = DEFAULT_ALGORITHM) -> pyotp.TOTP:
    return pyotp.TOTP(secret_key, digits=digits, interval=period, digest=ALGORITHMS[algorithm])

def format_code(code: str) -> str:
    """Splits a code in two for readability, e.g. '123 456' or '1234 5678'."""
    middle = len(code) // 2
    return f"{code[:middle]} {code[middle:]}"

def parse_otpauth_uri(uri: str) -> dict:
    """Parses an otpauth://totp/ URI (the contents of a 2FA QR code).

    Returns a dict with issuer_name, account_name, secret_key, digits, period, and algorithm.
    The issuer may be empty if the URI doesn't include one.

    Raises:
        ValueError: If the URI isn't a supported TOTP URI.
    """
    uri = uri.strip()
    if uri.lower().startswith("otpauth-migration://"):
        raise ValueError("Google Authenticator export codes aren't supported. Export or scan each account's own QR code instead.")

    parsed = urlparse(uri)
    if parsed.scheme.lower() != "otpauth":
        raise ValueError("Not a 2FA (otpauth://) link.")
    if parsed.netloc.lower() != "totp":
        raise ValueError("Only time-based (TOTP) codes are supported.")

    params = {key.lower(): values[0] for key, values in parse_qs(parsed.query).items()}
    secret_key = params.get("secret", "")
    if not secret_key:
        raise ValueError("The 2FA link doesn't contain a secret key.")

    label = unquote(parsed.path.lstrip("/"))
    label_issuer, _, account_name = label.rpartition(":")
    issuer_name = params.get("issuer") or label_issuer

    try:
        digits = int(params.get("digits", DEFAULT_DIGITS))
        period = int(params.get("period", DEFAULT_PERIOD))
    except ValueError:
        raise ValueError("The 2FA link has an invalid code length or period.")
    algorithm = params.get("algorithm", DEFAULT_ALGORITHM).upper()
    validate_settings(digits, period, algorithm)

    return {
        "issuer_name": issuer_name.strip(),
        "account_name": account_name.strip(),
        "secret_key": secret_key,
        "digits": digits,
        "period": period,
        "algorithm": algorithm,
    }
