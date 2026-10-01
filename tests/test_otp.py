import base64
import pytest
from core import otp

def b32(ascii_secret: str) -> str:
    return base64.b32encode(ascii_secret.encode()).decode()

# Test vectors from RFC 6238, Appendix B (8 digits, 30 second period)
@pytest.mark.parametrize("algorithm, secret, timestamp, expected", [
    ("SHA1", "12345678901234567890", 59, "94287082"),
    ("SHA1", "12345678901234567890", 1111111109, "07081804"),
    ("SHA256", "12345678901234567890123456789012", 59, "46119246"),
    ("SHA256", "12345678901234567890123456789012", 1234567890, "91819424"),
    ("SHA512", "1234567890123456789012345678901234567890123456789012345678901234", 59, "90693936"),
    ("SHA512", "1234567890123456789012345678901234567890123456789012345678901234", 20000000000, "47863826"),
])
def test_rfc6238_vectors(algorithm, secret, timestamp, expected):
    totp = otp.make_totp(b32(secret), digits=8, period=30, algorithm=algorithm)
    assert totp.at(timestamp) == expected

def test_period_changes_code_window():
    totp = otp.make_totp("JBSWY3DPEHPK3PXP", period=60)
    assert totp.at(0) == totp.at(59)
    assert totp.interval == 60

@pytest.mark.parametrize("code, expected", [("123456", "123 456"), ("1234567", "123 4567"), ("12345678", "1234 5678")])
def test_format_code(code, expected):
    assert otp.format_code(code) == expected

def test_parse_full_uri():
    token = otp.parse_otpauth_uri(
        "otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=60&algorithm=sha256")
    assert token == {"issuer_name": "GitHub", "account_name": "alice@example.com", "secret_key": "JBSWY3DPEHPK3PXP",
                     "digits": 8, "period": 60, "algorithm": "SHA256"}

def test_parse_minimal_uri_uses_defaults():
    token = otp.parse_otpauth_uri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
    assert token["issuer_name"] == ""
    assert token["account_name"] == "alice"
    assert (token["digits"], token["period"], token["algorithm"]) == (6, 30, "SHA1")

def test_parse_issuer_from_label_only():
    token = otp.parse_otpauth_uri("otpauth://totp/Example%20Co:bob?secret=JBSWY3DPEHPK3PXP")
    assert (token["issuer_name"], token["account_name"]) == ("Example Co", "bob")

def test_issuer_parameter_wins_over_label():
    token = otp.parse_otpauth_uri("otpauth://totp/Old:bob?secret=JBSWY3DPEHPK3PXP&issuer=New")
    assert token["issuer_name"] == "New"

@pytest.mark.parametrize("uri, message", [
    ("https://example.com", "Not a 2FA"),
    ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "time-based"),
    ("otpauth://totp/x?issuer=X", "secret key"),
    ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5", "Code length"),
    ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=abc", "invalid code length"),
    ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "Algorithm"),
    ("otpauth-migration://offline?data=abc", "Google Authenticator"),
])
def test_parse_rejects_unsupported(uri, message):
    with pytest.raises(ValueError, match=message):
        otp.parse_otpauth_uri(uri)
