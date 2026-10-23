from cryptography.hazmat.primitives.asymmetric import rsa as legacy_rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class PaymentCryptoService:
    def __init__(self):
        # VULNERABILITY 1: RSA-2048 key generation (Critical / HNDL risk)
        # Harvest-Now-Decrypt-Later risk for payment card tokens
        self.private_key = legacy_rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def encrypt_payment_payload(self, sensitive_data: bytes) -> bytes:
        return self.public_key.encrypt(
            sensitive_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_payment_payload(self, ciphertext: bytes) -> bytes:
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
