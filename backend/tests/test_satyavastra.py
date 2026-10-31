import datetime
from security import (
    encrypt_field, decrypt_field, encrypt_bytes, decrypt_bytes,
    hash_password, verify_password, sign_qr_payload, verify_qr_signature
)
from services import FraudDetectionEngine, MicroWeaveFeasibility

def test_encryption_roundtrip():
    original = "Niranjan Meher | Barpali, Bargarh"
    ciphertext = encrypt_field(original)
    assert ciphertext.startswith("AES256GCM:")
    assert decrypt_field(ciphertext) == original

def test_encryption_tamper_fails():
    ciphertext = encrypt_field("Secret Weaver Record")
    tampered = ciphertext[:-4] + "AAAA"
    assert "DECRYPTION_FAILED" in decrypt_field(tampered)

def test_file_bytes_encryption():
    raw_bytes = b"Sample high-resolution yarn structure"
    encrypted = encrypt_bytes(raw_bytes)
    assert decrypt_bytes(encrypted) == raw_bytes

def test_password_hashing():
    pin = "1234"
    hashed = hash_password(pin)
    assert verify_password("1234", hashed) is True
    assert verify_password("9999", hashed) is False

def test_qr_signature_verification():
    serial = "OR-SMB-2026-9041"
    exp = int((datetime.datetime.utcnow() + datetime.timedelta(days=120)).timestamp())
    sig = sign_qr_payload(serial, exp)
    assert verify_qr_signature(serial, exp, sig) is True
    assert verify_qr_signature("OR-SMB-2026-FAKE", exp, sig) is False

def test_fraud_engine_velocity_detection():
    class MockScan:
        def __init__(self, serial, scanned_at, ip):
            self.serial = serial
            self.scanned_at = scanned_at
            self.ip_address = ip

    now = datetime.datetime.utcnow()
    recent = [
        MockScan("OR-SMB-2026-9041", now - datetime.timedelta(seconds=10), "1.1.1.1"),
        MockScan("OR-SMB-2026-9041", now - datetime.timedelta(seconds=20), "1.1.1.1"),
        MockScan("OR-SMB-2026-9041", now - datetime.timedelta(seconds=30), "1.1.1.1")
    ]
    is_fraud, reason, lat = FraudDetectionEngine.evaluate_scan("OR-SMB-2026-9041", recent, "1.1.1.1")
    assert is_fraud is True
    assert "velocity" in reason.lower()
    assert lat < 1.2

def test_microweave_cosine_similarity():
    v1 = [0.1] * 16
    v2 = [0.1] * 16
    assert MicroWeaveFeasibility.compare_fingerprints(v1, v2) == 1.0
