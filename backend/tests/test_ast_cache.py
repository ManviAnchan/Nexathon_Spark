import time
import tempfile
import hashlib
from pathlib import Path
import pytest

from keynova.services.cache.ast_cache import AstCacheManager, AST_RULE_VERSION, get_ast_cache
from keynova.services.scanner.python_ast import scan_python_file, AstCryptoFinding


class TestAstCacheManagerUnit:
    """Unit tests for the content-addressable SQLite AST Cache Manager."""

    def test_cache_initialization_and_tables(self, tmp_path):
        db_file = tmp_path / "cache.db"
        cache = AstCacheManager(db_path=db_file)
        assert db_file.exists()
        stats = cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["hit_ratio"] == 0.0

    def test_in_memory_cache_support(self):
        cache = AstCacheManager(db_path=":memory:")
        sample_code = "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)"
        assert cache.get(sample_code) is None
        stats = cache.get_stats()
        assert stats["misses"] == 1
        assert stats["hits"] == 0

        findings = [{"algorithm": "RSA-2048", "severity": "critical", "hndl": True}]
        cache.set(sample_code, findings, file_path="crypto.py")

        cached = cache.get(sample_code)
        assert cached is not None
        assert len(cached) == 1
        assert cached[0]["algorithm"] == "RSA-2048"

        stats2 = cache.get_stats()
        assert stats2["hits"] == 1
        assert stats2["misses"] == 1
        assert stats2["hit_ratio"] == 0.5

    def test_deterministic_key_computation(self):
        content = "import hashlib\nhashlib.md5(b'test').hexdigest()"
        expected_key = hashlib.sha256(content.encode("utf-8") + AST_RULE_VERSION.encode("utf-8")).hexdigest()
        computed_key = AstCacheManager.compute_key(content, AST_RULE_VERSION)
        assert computed_key == expected_key

        # Key changes when content changes
        altered_content = content + "\n# comment"
        altered_key = AstCacheManager.compute_key(altered_content, AST_RULE_VERSION)
        assert computed_key != altered_key

        # Key changes when rule version changes
        rule_v2_key = AstCacheManager.compute_key(content, "keynova-ast-v2.0.0")
        assert computed_key != rule_v2_key

    def test_content_invalidation_lifecycle(self, tmp_path):
        cache = AstCacheManager(db_path=tmp_path / "invalidation.db")
        code_v1 = "import hashlib\nh = hashlib.sha1(b'data')"
        findings_v1 = [{"algorithm": "SHA-1", "severity": "low"}]
        cache.set(code_v1, findings_v1, file_path="hasher.py")

        # Cache hit for v1
        assert cache.get(code_v1) == findings_v1

        # Code modified to SHA-256 (PQC/secure)
        code_v2 = "import hashlib\nh = hashlib.sha256(b'data')"
        # Must be cache miss for v2
        assert cache.get(code_v2) is None

        findings_v2 = [{"algorithm": "SHA-256", "severity": "quantum_safe"}]
        cache.set(code_v2, findings_v2, file_path="hasher.py")
        assert cache.get(code_v2) == findings_v2

    def test_cache_clear_and_reset(self, tmp_path):
        cache = AstCacheManager(db_path=tmp_path / "clear_test.db")
        code = "secret = 123"
        cache.get(code)  # miss
        cache.set(code, [{"rule": "test"}])
        cache.get(code)  # hit

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1

        cache.clear()
        stats_cleared = cache.get_stats()
        assert stats_cleared["hits"] == 0
        assert stats_cleared["misses"] == 0
        assert cache.get(code) is None  # miss after clear


class TestAstCacheBenchmarkAndIntegration:
    """Integration and performance tests demonstrating speedup."""

    def test_latency_benchmark_cache_speedup(self, tmp_path):
        cache = AstCacheManager(db_path=tmp_path / "bench.db")
        py_file = tmp_path / "heavy_crypto.py"
        code_content = """
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
import hashlib
import hmac
import secrets

class PaymentCryptoService:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._private_key = None

    def initialize_keys(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self._ec_key = ec.generate_private_key(ec.SECP256R1())

    def sign_transaction(self, tx_bytes: bytes) -> bytes:
        digest = hashlib.sha1(tx_bytes).hexdigest()
        legacy_hash = hashlib.md5(tx_bytes).hexdigest()
        token = secrets.token_hex(32)
        mac = hmac.new(b"secret", tx_bytes, "sha256").digest()
        return mac

    def verify_transaction(self, signature: bytes, tx_bytes: bytes) -> bool:
        h1 = hashlib.md5(tx_bytes).hexdigest()
        h2 = hashlib.sha1(tx_bytes).hexdigest()
        return len(signature) > 0
"""
        py_file.write_text(code_content, encoding="utf-8")

        # 1. Warm-up and populate cache
        first_scan = scan_python_file(py_file, relative_to=tmp_path, use_cache=False)
        assert len(first_scan) >= 3

        # Store in cache
        cache.set(code_content, [f.to_dict() for f in first_scan], file_path="heavy_crypto.py")

        # 2. Benchmark raw AST parse
        num_iterations = 100
        start_ast = time.perf_counter()
        for _ in range(num_iterations):
            _ = scan_python_file(py_file, relative_to=tmp_path, use_cache=False)
        dur_ast = time.perf_counter() - start_ast

        # 3. Benchmark Cache Lookup
        start_cache = time.perf_counter()
        for _ in range(num_iterations):
            _ = cache.get(code_content)
        dur_cache = time.perf_counter() - start_cache

        speedup = dur_ast / max(dur_cache, 1e-6)
        assert speedup > 3.0, f"Expected cache speedup >3x, got {speedup:.2f}x (AST: {dur_ast*1000:.2f}ms vs Cache: {dur_cache*1000:.2f}ms)"

    def test_scan_python_file_cache_integration(self, tmp_path):
        py_file = tmp_path / "auth_service.py"
        py_file.write_text("import hashlib\nhashlib.md5(b'token')", encoding="utf-8")

        # First scan: cache miss, populates cache
        findings_1 = scan_python_file(py_file, relative_to=tmp_path, use_cache=True)
        assert len(findings_1) == 1
        assert findings_1[0].algorithm == "MD5"

        # Second scan: cache hit, exact same findings
        findings_2 = scan_python_file(py_file, relative_to=tmp_path, use_cache=True)
        assert len(findings_2) == 1
        assert findings_2[0].algorithm == "MD5"
        assert findings_2[0].file_path == str(py_file.relative_to(tmp_path))
