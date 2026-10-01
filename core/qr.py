from PIL import Image

def decode_qr_codes(image: Image.Image) -> list[str]:
    """Returns the text of every QR code found in the image.

    Raises:
        ImportError: If OpenCV (opencv-python) isn't installed.
    """
    import cv2 # Imported here so the rest of the app works without OpenCV
    import numpy as np

    pixels = np.array(image.convert("L"))
    detector = cv2.QRCodeDetector()
    found, texts, _, _ = detector.detectAndDecodeMulti(pixels)
    results = [text for text in texts if text] if found else []
    if not results:
        # Multi-code detection sometimes misses a lone code that single detection finds
        text, _, _ = detector.detectAndDecode(pixels)
        if text:
            results.append(text)
    return results
