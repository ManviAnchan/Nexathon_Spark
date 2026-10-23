import hashlib

class PasswordHasher:
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        # REMEDIATED: SHA-3-512 Quantum-Resistant Hash (Keccak sponge function)
        # 512-bit output provides 256-bit Grover quantum collision resistance
        combined = f"{salt}:{password}".encode("utf-8")
        return hashlib.sha3_512(combined).hexdigest()

    @staticmethod
    def verify_password(password: str, salt: str, expected_hash: str) -> bool:
        return PasswordHasher.hash_password(password, salt) == expected_hash
