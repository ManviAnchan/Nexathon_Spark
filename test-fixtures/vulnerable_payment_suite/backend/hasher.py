import hashlib

class PasswordHasher:
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        # VULNERABILITY 3: MD5 password hashing (Low / classical weakness)
        # Insecure for passwords and collision-vulnerable
        combined = f"{salt}:{password}".encode("utf-8")
        return hashlib.md5(combined).hexdigest()

    @staticmethod
    def verify_password(password: str, salt: str, expected_hash: str) -> bool:
        return PasswordHasher.hash_password(password, salt) == expected_hash
