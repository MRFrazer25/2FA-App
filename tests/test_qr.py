import pytest
from PIL import Image
from core.qr import decode_qr_codes

cv2 = pytest.importorskip("cv2")

URI = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=60&algorithm=SHA256"

def qr_image(text: str, scale: int = 8) -> Image.Image:
    pixels = cv2.QRCodeEncoder.create().encode(text)
    pixels = cv2.resize(pixels, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    pixels = cv2.copyMakeBorder(pixels, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    return Image.fromarray(pixels)

def test_decodes_qr_image():
    assert decode_qr_codes(qr_image(URI)) == [URI]

@pytest.mark.parametrize("screen_size", [(1920, 1080), (3840, 1080)])
def test_finds_small_qr_code_on_a_screenshot(screen_size):
    screen = Image.new("RGB", screen_size, (240, 240, 240))
    screen.paste(qr_image(URI).resize((220, 220)), (screen_size[0] - 500, 300))
    assert decode_qr_codes(screen) == [URI]

def test_no_qr_code():
    assert decode_qr_codes(Image.new("RGB", (800, 600), "white")) == []
