"""
Comprehensive test suite for Keynova's SSRF-Hardened TLS Socket Inspector
(backend/keynova/services/tls/inspector.py) and API Endpoint (backend/keynova/api/v1/tls.py).

Validates:
- Input validation (valid/invalid hostnames, ports, length limits, URLs/paths)
- Defense-in-depth IP classification (IPv4, IPv6, IPv4-mapped IPv6, CGNAT, metadata, etc.)
- Strict pre-connection DNS resolution and validation of all resolved IPs
- Fail-closed behavior on mixed DNS responses (public + private records)
- Zero-TOCTOU guarantee: direct socket connection to validated numeric IP (preventing DNS rebinding)
- Preservation of Server Name Indication (SNI) and certificate hostname validation
- Reliable TLS negotiation capture (version, cipher, subject, issuer, key size, PQC detection, is_pqc_hybrid)
- Non-fabrication on certificate verification failures and handshake timeouts
- Reliable socket resource cleanup (close() on success and failure)
- 100% compatibility with TlsInspectionResponse Pydantic schema
- API endpoint POST /inspect response handling
"""

import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = str(Path(__file__).resolve().parent.parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import socket
import ssl
import ipaddress
from unittest.mock import patch, MagicMock
import pytest

from keynova.services.tls.inspector import (
    inspect_tls_endpoint,
    validate_and_resolve_host,
    resolve_and_validate_target,
    validate_inputs,
    is_prohibited_ip,
    SSRFSecurityViolation,
    TargetResolutionError,
    InputValidationError,
    BLOCKED_NETWORKS,
    PROHIBITED_IPV4_NETWORKS,
    PROHIBITED_IPV6_NETWORKS,
)
from keynova.core.models import TlsInspectionResponse, TlsInspectionRequest
from keynova.api.v1.tls import router as tls_router


# ============================================================================
# 1. INPUT VALIDATION TESTS
# ============================================================================

class TestTlsInputValidation:
    """Verifies that invalid or malformed hosts and ports are rejected immediately."""

    def test_valid_inputs_hostname_and_port(self):
        """Standard valid hostnames and ports must pass validation."""
        host, port = validate_inputs("api.example.com", 443)
        assert host == "api.example.com"
        assert port == 443

        host2, port2 = validate_inputs("  vault.internal.io  ", "8443")
        assert host2 == "vault.internal.io"
        assert port2 == 8443

    def test_invalid_host_types_and_empty(self):
        """None, empty strings, and non-strings must be rejected."""
        with pytest.raises(InputValidationError):
            validate_inputs("", 443)
        with pytest.raises(InputValidationError):
            validate_inputs("   ", 443)
        with pytest.raises(InputValidationError):
            validate_inputs(None, 443)
        with pytest.raises(InputValidationError):
            validate_inputs(12345, 443)

    def test_host_with_schemes_or_paths_rejected(self):
        """Hostnames containing URL schemes, paths, or query fragments must be rejected."""
        with pytest.raises(InputValidationError):
            validate_inputs("https://example.com", 443)
        with pytest.raises(InputValidationError):
            validate_inputs("http://example.com:443", 443)
        with pytest.raises(InputValidationError):
            validate_inputs("example.com/api/v1", 443)
        with pytest.raises(InputValidationError):
            validate_inputs("example.com?query=1", 443)
        with pytest.raises(InputValidationError):
            validate_inputs("example.com#frag", 443)

    def test_host_with_whitespace_or_control_chars_rejected(self):
        """Hostnames containing whitespace, newlines, or control characters must be rejected."""
        with pytest.raises(InputValidationError):
            validate_inputs("example .com", 443)
        with pytest.raises(InputValidationError):
            validate_inputs("example\n.com", 443)
        with pytest.raises(InputValidationError):
            validate_inputs("example\x00.com", 443)

    def test_host_exceeding_max_rfc_length(self):
        """Hostnames exceeding 253 characters must be rejected."""
        long_host = "a" * 254 + ".com"
        with pytest.raises(InputValidationError):
            validate_inputs(long_host, 443)

    def test_invalid_ports_rejected(self):
        """Ports outside [1, 65535] or non-integer values must be rejected."""
        invalid_ports = [0, -1, -443, 65536, 99999, "abc", "443.5", None]
        for p in invalid_ports:
            with pytest.raises(InputValidationError):
                validate_inputs("example.com", p)

    def test_inspect_tls_endpoint_handles_invalid_input_gracefully(self):
        """inspect_tls_endpoint returns a structured error response on input validation failure."""
        res = inspect_tls_endpoint("https://invalid.com", 443)
        assert res["is_safe"] is False
        assert res["resolved_ip"] == "invalid"
        assert "Invalid host format" in res["error"]
        # Verify Pydantic response model conformance
        TlsInspectionResponse(**res)


# ============================================================================
# 2. IP ADDRESS VALIDATION & SSRF SHIELD (is_prohibited_ip)
# ============================================================================

class TestIpAddressValidationAndSsrfShield:
    """Verifies that all private, loopback, link-local, multicast, and reserved ranges are blocked."""

    def test_prohibited_ipv4_loopback(self):
        """127.0.0.0/8 loopback block must be rejected."""
        for ip_str in ["127.0.0.1", "127.0.0.2", "127.1.2.3", "127.255.255.254"]:
            prohibited, reason = is_prohibited_ip(ipaddress.ip_address(ip_str))
            assert prohibited is True, f"Failed for {ip_str}"
            assert "Loopback" in reason or "prohibited" in reason

    def test_prohibited_ipv4_private_rf1918(self):
        """RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) must be rejected."""
        private_ips = [
            "10.0.0.1", "10.254.254.254", "10.255.255.255",
            "172.16.0.1", "172.24.1.1", "172.31.255.254",
            "192.168.0.1", "192.168.1.1", "192.168.254.254"
        ]
        for ip_str in private_ips:
            prohibited, reason = is_prohibited_ip(ipaddress.ip_address(ip_str))
            assert prohibited is True, f"Failed for {ip_str}"
            assert "Private" in reason or "prohibited" in reason

    def test_prohibited_ipv4_cloud_metadata_and_link_local(self):
        """169.254.0.0/16 (especially 169.254.169.254 AWS/GCP metadata) must be rejected."""
        for ip_str in ["169.254.169.254", "169.254.1.1", "169.254.254.254"]:
            prohibited, reason = is_prohibited_ip(ipaddress.ip_address(ip_str))
            assert prohibited is True, f"Failed for {ip_str}"
            assert "Link-local" in reason or "prohibited" in reason

    def test_prohibited_ipv4_unspecified_broadcast_and_multicast(self):
        """0.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4, and 255.255.255.255 must be rejected."""
        for ip_str in ["0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255"]:
            prohibited, reason = is_prohibited_ip(ipaddress.ip_address(ip_str))
            assert prohibited is True, f"Failed for {ip_str}"

    def test_prohibited_cgnat_and_documentation_ranges(self):
        """CGNAT (100.64.0.0/10) and documentation ranges (TEST-NET) must be rejected."""
        for ip_str in ["100.64.0.1", "100.127.255.254", "192.0.2.1", "198.51.100.1", "203.0.113.1"]:
            prohibited, reason = is_prohibited_ip(ipaddress.ip_address(ip_str))
            assert prohibited is True, f"Failed for {ip_str}"

    def test_prohibited_ipv6_loopback_and_private(self):
        """IPv6 loopback (::1), unique local (fc00::/7), link-local (fe80::/10), unspecified (::)."""
        for ip_str in ["::1", "::", "fc00::1", "fd00::dead:beef", "fe80::1", "ff02::1"]:
            prohibited, reason = is_prohibited_ip(ipaddress.ip_address(ip_str))
            assert prohibited is True, f"Failed for {ip_str}"

    def test_prohibited_ipv4_mapped_ipv6(self):
        """IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) must be unpacked and evaluated."""
        for ip_str in ["::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:192.168.1.1"]:
            prohibited, reason = is_prohibited_ip(ipaddress.ip_address(ip_str))
            assert prohibited is True, f"Failed for {ip_str}"
            assert "IPv4-mapped" in reason or "prohibited" in reason

    def test_allowed_public_ips(self):
        """Legitimate globally routable public IPs must be permitted."""
        public_ips = [
            "93.184.216.34",            # example.com
            "8.8.8.8",                  # Google DNS
            "1.1.1.1",                  # Cloudflare
            "151.101.1.69",             # Fastly
            "2606:4700:4700::1111",     # Cloudflare public IPv6
            "2001:4860:4860::8888",     # Google public IPv6
        ]
        for ip_str in public_ips:
            prohibited, reason = is_prohibited_ip(ipaddress.ip_address(ip_str))
            assert prohibited is False, f"Expected safe public IP for {ip_str}, got reason: {reason}"
            assert reason == ""


# ============================================================================
# 3. DNS RESOLUTION & REBINDING DEFENSE
# ============================================================================

class TestDnsResolutionAndRebindingDefense:
    """Verifies pre-connection DNS inspection, multi-IP inspection, and anti-rebinding."""

    @patch("socket.getaddrinfo")
    def test_dns_resolution_failure_handled_gracefully(self, mock_getaddrinfo):
        """DNS resolution errors (e.g. NXDOMAIN) return an unresolved error without crashing."""
        mock_getaddrinfo.side_effect = socket.gaierror(-2, "Name or service not known")
        res = inspect_tls_endpoint("nonexistent-domain-xyz.org", 443)
        assert res["is_safe"] is False
        assert res["resolved_ip"] == "unresolved"
        assert "DNS resolution failed" in res["error"]
        TlsInspectionResponse(**res)

    @patch("socket.getaddrinfo")
    def test_empty_dns_response_handled_gracefully(self, mock_getaddrinfo):
        """If DNS returns an empty list, inspector fails closed."""
        mock_getaddrinfo.return_value = []
        res = inspect_tls_endpoint("empty-dns.example.com", 443)
        assert res["is_safe"] is False
        assert res["resolved_ip"] == "unresolved"
        assert "no addresses" in res["error"].lower()
        TlsInspectionResponse(**res)

    @patch("socket.getaddrinfo")
    def test_single_private_ip_blocked(self, mock_getaddrinfo):
        """A domain resolving to 127.0.0.1 or 10.0.0.1 must be blocked."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        ]
        res = inspect_tls_endpoint("evil-local.example.com", 443)
        assert res["is_safe"] is False
        assert res["resolved_ip"] == "blocked"
        assert "SSRF violation" in res["error"]
        assert "Loopback" in res["error"]
        TlsInspectionResponse(**res)

    @patch("socket.getaddrinfo")
    def test_mixed_dns_public_and_private_addresses_rejected(self, mock_getaddrinfo):
        """
        CRITICAL TEST: If a domain resolves to BOTH a public IP and a private/prohibited IP,
        the inspector MUST fail closed and reject the host entirely.
        """
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),  # Public
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 443)),        # Private!
        ]
        res = inspect_tls_endpoint("mixed-dual-homed.example.com", 443)
        assert res["is_safe"] is False
        assert res["resolved_ip"] == "blocked"
        assert "SSRF violation" in res["error"]
        assert "10.0.0.1" in res["error"]
        TlsInspectionResponse(**res)

    @patch("socket.getaddrinfo")
    def test_mixed_dns_public_and_metadata_ip_rejected(self, mock_getaddrinfo):
        """A public IP mixed with 169.254.169.254 must be blocked immediately."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 443)),
        ]
        res = inspect_tls_endpoint("metadata-rebinding.example.com", 443)
        assert res["is_safe"] is False
        assert res["resolved_ip"] == "blocked"
        assert "169.254.169.254" in res["error"]
        TlsInspectionResponse(**res)

    @patch("keynova.services.tls.inspector.ssl.create_default_context")
    @patch("socket.create_connection")
    @patch("socket.getaddrinfo")
    def test_prevention_of_second_uncontrolled_dns_resolution(
        self, mock_getaddrinfo, mock_create_connection, mock_ssl_context
    ):
        """
        CRITICAL ANTI-REBINDING TEST:
        socket.create_connection MUST be called with the numeric validated IP ('93.184.216.34'),
        NOT the hostname string ('safe.example.com').
        This ensures zero secondary DNS resolution occurs.
        """
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
        ]

        # Setup mock socket and TLS context
        mock_raw_sock = MagicMock()
        mock_create_connection.return_value = mock_raw_sock

        mock_tls_sock = MagicMock()
        mock_tls_sock.version.return_value = "TLSv1.3"
        mock_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_tls_sock.getpeercert.return_value = {
            "subject": ((("commonName", "safe.example.com"),),),
            "issuer": ((("organizationName", "DigiCert"),),),
        }
        mock_ctx_instance = MagicMock()
        mock_ctx_instance.wrap_socket.return_value = mock_tls_sock
        mock_ssl_context.return_value = mock_ctx_instance

        res = inspect_tls_endpoint("safe.example.com", 443)

        # 1. Assert socket.create_connection connected directly to the NUMERIC IP address
        mock_create_connection.assert_called_once()
        args, kwargs = mock_create_connection.call_args
        target_addr, target_port = args[0]
        assert target_addr == "93.184.216.34", f"Expected numeric IP '93.184.216.34', got {target_addr}"
        assert target_port == 443

        # 2. Assert TLS wrap_socket used clean hostname for SNI and certificate verification
        mock_ctx_instance.wrap_socket.assert_called_once_with(mock_raw_sock, server_hostname="safe.example.com")

        # 3. Assert results
        assert res["is_safe"] is True
        assert res["resolved_ip"] == "93.184.216.34"
        assert res["tls_version"] == "TLSv1.3"
        assert res["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert res["is_pqc_hybrid"] is False
        TlsInspectionResponse(**res)


# ============================================================================
# 4. TLS HANDSHAKE, CERTIFICATE VERIFICATION & RESOURCE CLEANUP
# ============================================================================

class TestTlsHandshakeAndCertificateInspection:
    """Verifies certificate parsing, error handling, timeouts, and socket cleanup."""

    @patch("keynova.services.tls.inspector.ssl.create_default_context")
    @patch("socket.create_connection")
    @patch("socket.getaddrinfo")
    def test_successful_tls_inspection(self, mock_getaddrinfo, mock_create_connection, mock_ssl_context):
        """Verified TLS 1.3 handshake correctly extracts certificate subject, issuer, and cipher."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 443))
        ]
        mock_raw_sock = MagicMock()
        mock_create_connection.return_value = mock_raw_sock

        mock_tls_sock = MagicMock()
        mock_tls_sock.version.return_value = "TLSv1.3"
        mock_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_tls_sock.getpeercert.return_value = {
            "subject": ((("commonName", "cloudflare.com"),),),
            "issuer": ((("organizationName", "Cloudflare, Inc."),),),
        }
        mock_ctx_instance = MagicMock()
        mock_ctx_instance.wrap_socket.return_value = mock_tls_sock
        mock_ssl_context.return_value = mock_ctx_instance

        res = inspect_tls_endpoint("cloudflare.com", 443)

        assert res["is_safe"] is True
        assert res["host"] == "cloudflare.com"
        assert res["port"] == 443
        assert res["resolved_ip"] == "1.1.1.1"
        assert res["tls_version"] == "TLSv1.3"
        assert res["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert res["certificate_subject"] == "cloudflare.com"
        assert res["certificate_issuer"] == "Cloudflare, Inc."
        assert res["key_size"] == 256
        assert res["quantum_safe"] is False
        assert res["is_pqc_hybrid"] is False
        assert res["error"] is None

        # Sockets must be closed
        mock_tls_sock.close.assert_called_once()
        TlsInspectionResponse(**res)

    @patch("keynova.services.tls.inspector.ssl.create_default_context")
    @patch("socket.create_connection")
    @patch("socket.getaddrinfo")
    def test_quantum_safe_hybrid_pqc_detection(self, mock_getaddrinfo, mock_create_connection, mock_ssl_context):
        """Negotiated ciphers containing ML-KEM or Kyber must be classified as quantum_safe=True and is_pqc_hybrid=True."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        ]
        mock_raw_sock = MagicMock()
        mock_create_connection.return_value = mock_raw_sock

        mock_tls_sock = MagicMock()
        mock_tls_sock.version.return_value = "TLSv1.3"
        mock_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384_X25519MLKEM768", "TLSv1.3", 256)
        mock_tls_sock.getpeercert.return_value = {
            "subject": ((("commonName", "pqc.google.com"),),),
            "issuer": ((("organizationName", "Google Trust Services"),),),
        }
        mock_ctx_instance = MagicMock()
        mock_ctx_instance.wrap_socket.return_value = mock_tls_sock
        mock_ssl_context.return_value = mock_ctx_instance

        res = inspect_tls_endpoint("pqc.google.com", 443)
        assert res["is_safe"] is True
        assert res["quantum_safe"] is True
        assert res["is_pqc_hybrid"] is True
        TlsInspectionResponse(**res)

    @patch("keynova.services.tls.inspector.ssl.create_default_context")
    @patch("socket.create_connection")
    @patch("socket.getaddrinfo")
    def test_certificate_verification_failure_never_reports_fake_details(
        self, mock_getaddrinfo, mock_create_connection, mock_ssl_context
    ):
        """
        SECURITY REQUIREMENT: Expired/untrusted certificates must fail validation (is_safe=False),
        mark certificate_subject as UNVERIFIED, and NEVER fabricate fake certificate info.
        """
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
        ]
        mock_raw_sock = MagicMock()
        mock_create_connection.return_value = mock_raw_sock

        mock_ctx_instance = MagicMock()
        cert_error = ssl.SSLCertVerificationError(1, "certificate verify failed: certificate has expired")
        mock_ctx_instance.wrap_socket.side_effect = cert_error
        mock_ssl_context.return_value = mock_ctx_instance

        res = inspect_tls_endpoint("expired.example.com", 443)

        assert res["is_safe"] is False
        assert res["certificate_subject"] == "UNVERIFIED"
        assert res["certificate_issuer"] == "UNVERIFIED"
        assert res["cipher_suite"] == "N/A"
        assert res["tls_version"] == "N/A"
        assert "Certificate verification failed" in res["error"]

        # Socket must still be closed
        mock_raw_sock.close.assert_called_once()
        TlsInspectionResponse(**res)

    @patch("socket.create_connection")
    @patch("socket.getaddrinfo")
    def test_connection_timeout_handled_cleanly(self, mock_getaddrinfo, mock_create_connection):
        """Connection timeouts return structured error and do not hang."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
        ]
        mock_create_connection.side_effect = socket.timeout("Connection timed out")

        res = inspect_tls_endpoint("timeout.example.com", 443, timeout=2.0)
        assert res["is_safe"] is False
        assert res["tls_version"] == "N/A"
        assert "timed out" in res["error"]
        TlsInspectionResponse(**res)

    @patch("socket.create_connection")
    @patch("socket.getaddrinfo")
    def test_connection_refused_handled_cleanly(self, mock_getaddrinfo, mock_create_connection):
        """Connection refused errors return structured error."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
        ]
        mock_create_connection.side_effect = ConnectionRefusedError("Connection refused")

        res = inspect_tls_endpoint("refused.example.com", 443)
        assert res["is_safe"] is False
        assert "Connection refused" in res["error"]
        TlsInspectionResponse(**res)


# ============================================================================
# 5. BACKWARDS COMPATIBILITY & EXPORT CONSTANTS TESTS
# ============================================================================

class TestTlsBackwardsCompatibility:
    """Verifies that validate_and_resolve_host, PROHIBITED networks, and BLOCKED_NETWORKS preserve compatibility."""

    def test_prohibited_and_blocked_networks_constants_available(self):
        """PROHIBITED_IPV4_NETWORKS, PROHIBITED_IPV6_NETWORKS, and BLOCKED_NETWORKS must be defined."""
        assert len(PROHIBITED_IPV4_NETWORKS) >= 10
        assert len(PROHIBITED_IPV6_NETWORKS) >= 5
        assert len(BLOCKED_NETWORKS) == len(PROHIBITED_IPV4_NETWORKS) + len(PROHIBITED_IPV6_NETWORKS)
        assert any(ipaddress.ip_network("127.0.0.0/8") == net for net in BLOCKED_NETWORKS)
        assert any(ipaddress.ip_network("10.0.0.0/8") == net for net in BLOCKED_NETWORKS)
        assert any(ipaddress.ip_network("::1/128") == net for net in BLOCKED_NETWORKS)

    @patch("socket.getaddrinfo")
    def test_validate_and_resolve_host_success(self, mock_getaddrinfo):
        """validate_and_resolve_host returns IP on valid public domain."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
        ]
        ip = validate_and_resolve_host("safe.example.com")
        assert ip == "93.184.216.34"

    @patch("socket.getaddrinfo")
    def test_validate_and_resolve_host_raises_ssrf_violation(self, mock_getaddrinfo):
        """validate_and_resolve_host raises SSRFSecurityViolation on private IP."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.1", 443))
        ]
        with pytest.raises(SSRFSecurityViolation):
            validate_and_resolve_host("intranet.example.com")


# ============================================================================
# 6. FASTAPI API ROUTER INTEGRATION TESTS
# ============================================================================

class TestTlsApiEndpoint:
    """Verifies POST /inspect endpoint behavior."""

    def test_router_inspect_handler_success(self):
        """API handler correctly processes request and returns TlsInspectionResponse."""
        from keynova.api.v1.tls import inspect_tls

        with patch("keynova.api.v1.tls.inspect_tls_endpoint") as mock_inspect:
            mock_inspect.return_value = {
                "host": "cloudflare.com",
                "port": 443,
                "resolved_ip": "1.1.1.1",
                "is_safe": True,
                "tls_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "certificate_subject": "cloudflare.com",
                "certificate_issuer": "Cloudflare, Inc.",
                "key_size": 256,
                "quantum_safe": False,
                "is_pqc_hybrid": False,
                "error": None
            }
            req = TlsInspectionRequest(host="cloudflare.com", port=443)
            resp = inspect_tls(req)
            assert resp.host == "cloudflare.com"
            assert resp.is_safe is True
            assert resp.tls_version == "TLSv1.3"
            assert resp.cipher_suite == "TLS_AES_256_GCM_SHA384"
            assert resp.quantum_safe is False
            assert resp.is_pqc_hybrid is False

    def test_router_inspect_handler_blocked(self):
        """API handler correctly returns blocked SSRF response."""
        from keynova.api.v1.tls import inspect_tls

        with patch("keynova.api.v1.tls.inspect_tls_endpoint") as mock_inspect:
            mock_inspect.return_value = {
                "host": "localhost",
                "port": 443,
                "resolved_ip": "blocked",
                "is_safe": False,
                "tls_version": "N/A",
                "cipher_suite": "N/A",
                "certificate_subject": "N/A",
                "certificate_issuer": "N/A",
                "key_size": 0,
                "quantum_safe": False,
                "is_pqc_hybrid": False,
                "error": "SSRF violation: localhost resolves to prohibited address 127.0.0.1"
            }
            req = TlsInspectionRequest(host="localhost", port=443)
            resp = inspect_tls(req)
            assert resp.is_safe is False
            assert resp.resolved_ip == "blocked"
            assert "SSRF violation" in resp.error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
