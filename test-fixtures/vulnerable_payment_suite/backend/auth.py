from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

class TokenAuthService:
    def __init__(self):
        # VULNERABILITY 2: ECC SECP256R1 ECDSA signing (High quantum risk under Shor's algorithm)
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.verifying_key = self.signing_key.public_key()

    def sign_auth_jwt(self, claims_hash: bytes) -> bytes:
        return self.signing_key.sign(claims_hash, ec.ECDSA(hashes.SHA256()))

    def verify_auth_jwt(self, claims_hash: bytes, signature: bytes) -> bool:
        try:
            self.verifying_key.verify(signature, claims_hash, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
