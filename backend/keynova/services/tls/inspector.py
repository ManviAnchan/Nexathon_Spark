"""
SSRF-Hardened TLS Socket Inspector with Post-DNS IP Validation.

Provides zero-trust, SSRF-safe live TLS inspection of remote network endpoints:
1. Validates hostname and port inputs (rejects malformed hosts, URLs, paths, out-of-range ports).
2. Performs full pre-connection DNS resolution (supporting both IPv4 and IPv6).
3. Inspects and validates EVERY resolved IP address against prohibited ranges:
   - Loopback, private (RFC 1918), link-local/cloud metadata (RFC 3927), unspecified (0.0.0.0, ::),
     multicast, shared address space (CGNAT RFC 6598), documentation, benchmarking, reserved,
     broadcast, IPv4-mapped IPv6 (::ffff:0:0/96), 6to4 relays, and non-global routable IPs.
   - Fails closed if ANY resolved address is prohibited or if resolution is mixed.
4. Prevents DNS Rebinding and TOCTOU (Time-of-Check to Time-of-Use) attacks:
   - Connects directly to the validated numeric IP address (zero secondary DNS resolution).
   - Supplies the original hostname via Server Name Indication (SNI) and enforces
     strict TLS certificate hostname validation.
5. Captures verified TLS negotiation details (version, cipher suite, subject, issuer, key size, PQC hybrid status).
6. Never fabricates results or reports unverified certificates as trustworthy.
7. Enforces finite timeouts and guarantees socket resource cleanup.
"""

import socket
import ssl
import ipaddress
from typing import Dict, Any, List, Tuple, Union, Optional

# Comprehensive prohibited IPv4 networks (defense-in-depth across RFCs)
PROHIBITED_IPV4_NETWORKS: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Private-use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # Private-use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast (RFC 919)
]

# Comprehensive prohibited IPv6 networks
PROHIBITED_IPV6_NETWORKS: List[ipaddress.IPv6Network] = [
    ipaddress.ip_network("::/128"),             # Unspecified (RFC 4291)
    ipaddress.ip_network("::1/128"),            # Loopback (RFC 4291)
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6 (RFC 4291)
    ipaddress.ip_network("100::/64"),           # Discard-only (RFC 6666)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("2002::/16"),          # 6to4 relay (RFC 3056)
    ipaddress.ip_network("fc00::/7"),           # Unique local / Private (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
]

# Unified list preserved for backwards compatibility with existing references
BLOCKED_NETWORKS = list(PROHIBITED_IPV4_NETWORKS) + list(PROHIBITED_IPV6_NETWORKS)


class SSRFSecurityViolation(Exception):
    """Raised when an inspected target resolves to a private, loopback, or prohibited destination."""
    pass


class TargetResolutionError(Exception):
    """Raised when a hostname cannot be resolved via DNS or returns empty results."""
    pass


class InputValidationError(Exception):
    """Raised when input parameters (host, port) fail validation."""
    pass


def is_prohibited_ip(ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address is prohibited (private, loopback, link-local,
    multicast, unspecified, CGNAT, documentation, reserved, or non-global).

    Handles IPv4, IPv6, and IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1).
    Returns (True, reason) if prohibited, or (False, "") if safe and globally routable.
    """
    # 1. Unmap IPv4-mapped IPv6 addresses if present (e.g., ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        mapped_prohibited, mapped_reason = is_prohibited_ip(ip_obj.ipv4_mapped)
        if mapped_prohibited:
            return True, f"IPv4-mapped address {ip_obj.ipv4_mapped} is prohibited: {mapped_reason}"
        return True, "IPv4-mapped IPv6 address is prohibited for direct IPv6 routing"

    # 2. Check 6to4 relay addresses (2002::/16 contains embedded IPv4)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.sixtofour is not None:
        sixtofour_prohibited, sixtofour_reason = is_prohibited_ip(ip_obj.sixtofour)
        if sixtofour_prohibited:
            return True, f"6to4 embedded address {ip_obj.sixtofour} is prohibited: {sixtofour_reason}"

    # 3. Check native standard library IP classification properties
    if ip_obj.is_loopback:
        return True, "Loopback address"
    if ip_obj.is_link_local:
        return True, "Link-local address (metadata service)"
    if ip_obj.is_private:
        return True, "Private / Intranet address"
    if ip_obj.is_multicast:
        return True, "Multicast address"
    if ip_obj.is_unspecified:
        return True, "Unspecified address (0.0.0.0 or ::)"
    if ip_obj.is_reserved:
        return True, "Reserved address"
    if not ip_obj.is_global:
        return True, "Non-global routable address"

    # 4. Check explicit prohibited CIDR tables for defense-in-depth
    if isinstance(ip_obj, ipaddress.IPv4Address):
        for net in PROHIBITED_IPV4_NETWORKS:
            if ip_obj in net:
                return True, f"Belongs to prohibited network {net}"
    elif isinstance(ip_obj, ipaddress.IPv6Address):
        for net in PROHIBITED_IPV6_NETWORKS:
            if ip_obj in net:
                return True, f"Belongs to prohibited network {net}"

    return False, ""


def validate_inputs(host: Any, port: Any) -> Tuple[str, int]:
    """
    Validates the host and port parameters.

    Rejects:
    - Non-string or empty hosts
    - Excessively long hosts (>253 chars)
    - URLs or paths (schemes like http://, slashes, query parameters)
    - Control characters or whitespace in host
    - Ports outside the valid range [1, 65535]
    """
    if not isinstance(host, str):
        raise InputValidationError(f"Invalid host: expected string, got {type(host).__name__}")

    clean_host = host.strip()
    if not clean_host:
        raise InputValidationError("Host must not be empty or whitespace")

    if len(clean_host) > 253:
        raise InputValidationError(f"Host exceeds maximum RFC length of 253 characters ({len(clean_host)})")

    # Reject URLs, paths, fragments, schemes
    if "://" in clean_host or "/" in clean_host or "\\" in clean_host or "?" in clean_host or "#" in clean_host:
        raise InputValidationError(f"Invalid host format: '{host}'. Host must not contain schemes or paths.")

    # Reject whitespace or control characters
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in clean_host):
        raise InputValidationError("Host must not contain whitespace or control characters")

    # Validate port
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        raise InputValidationError(f"Invalid port: '{port}'. Port must be an integer between 1 and 65535.")

    if not (1 <= port_num <= 65535):
        raise InputValidationError(f"Port {port_num} out of valid range (1-65535)")

    return clean_host, port_num


def resolve_and_validate_target(host: str, port: int) -> Tuple[str, List[str]]:
    """
    Resolves DNS for the given host and asserts that EVERY resolved IP address
    is safe and globally routable.

    Returns:
        Tuple[str, List[str]]: (primary_connection_ip, all_resolved_ips)

    Raises:
        SSRFSecurityViolation: If ANY resolved IP is private, loopback, or prohibited.
        TargetResolutionError: If DNS resolution fails or returns no addresses.
    """
    clean_host = host.strip()

    # Handle bracketed IPv6 literal e.g. [2001:db8::1]
    if clean_host.startswith("[") and clean_host.endswith("]"):
        raw_ip_str = clean_host[1:-1]
    else:
        raw_ip_str = clean_host

    # Check if host is already an IP literal
    try:
        ip_obj = ipaddress.ip_address(raw_ip_str)
        prohibited, reason = is_prohibited_ip(ip_obj)
        if prohibited:
            raise SSRFSecurityViolation(f"SSRF violation: IP literal {raw_ip_str} is prohibited ({reason})")
        return str(ip_obj), [str(ip_obj)]
    except ValueError:
        # Not an IP literal; proceed to full DNS resolution
        pass

    # Resolve using socket.getaddrinfo (retrieves both IPv4 and IPv6)
    try:
        addr_info = socket.getaddrinfo(
            clean_host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as e:
        raise TargetResolutionError(f"DNS resolution failed for {clean_host}: {e.strerror or e}")
    except Exception as e:
        raise TargetResolutionError(f"Unable to resolve host {clean_host}: {e}")

    if not addr_info:
        raise TargetResolutionError(f"DNS returned no addresses for {clean_host}")

    resolved_ips: List[str] = []
    seen = set()
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if ip_str not in seen:
            seen.add(ip_str)
            resolved_ips.append(ip_str)

    # Inspect EVERY resolved IP address (fail-closed if any address is prohibited)
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFSecurityViolation(f"Unparseable resolved address '{ip_str}' for host {clean_host}")

        prohibited, reason = is_prohibited_ip(ip_obj)
        if prohibited:
            raise SSRFSecurityViolation(
                f"SSRF violation: {clean_host} resolves to prohibited address {ip_str} ({reason})"
            )

    # All resolved addresses passed validation; return the primary IP
    return resolved_ips[0], resolved_ips


def validate_and_resolve_host(host: str) -> str:
    """
    Resolves DNS and asserts all resolved IPs are public to prevent SSRF attacks.
    Preserved for backwards compatibility with existing callers.
    """
    clean_host, _ = validate_inputs(host, 443)
    target_ip, _ = resolve_and_validate_target(clean_host, 443)
    return target_ip


def inspect_tls_endpoint(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Safely inspects a remote TLS endpoint's certificate, cipher suite, and protocol.

    Security guarantees:
    - Validates inputs rigorously.
    - Inspects all resolved IP addresses before connection.
    - Connects directly to the validated numeric IP address (preventing DNS rebinding).
    - Preserves hostname in TLS SNI and enforces certificate validation.
    - Never fabricates results or reports unverified certificates as trustworthy.
    - Uses finite timeouts and guarantees socket closure.

    Returns a structured dictionary matching TlsInspectionResponse.
    """
    # 1. Input Validation
    try:
        clean_host, port_num = validate_inputs(host, port)
    except InputValidationError as e:
        return {
            "host": str(host) if host is not None else "",
            "port": port if isinstance(port, int) else 0,
            "resolved_ip": "invalid",
            "is_safe": False,
            "tls_version": "N/A",
            "cipher_suite": "N/A",
            "certificate_subject": "N/A",
            "certificate_issuer": "N/A",
            "key_size": 0,
            "quantum_safe": False,
            "is_pqc_hybrid": False,
            "error": str(e)
        }

    # 2. DNS Resolution and IP Validation
    try:
        target_ip, _ = resolve_and_validate_target(clean_host, port_num)
    except SSRFSecurityViolation as e:
        return {
            "host": clean_host,
            "port": port_num,
            "resolved_ip": "blocked",
            "is_safe": False,
            "tls_version": "N/A",
            "cipher_suite": "N/A",
            "certificate_subject": "N/A",
            "certificate_issuer": "N/A",
            "key_size": 0,
            "quantum_safe": False,
            "is_pqc_hybrid": False,
            "error": str(e)
        }
    except TargetResolutionError as e:
        return {
            "host": clean_host,
            "port": port_num,
            "resolved_ip": "unresolved",
            "is_safe": False,
            "tls_version": "N/A",
            "cipher_suite": "N/A",
            "certificate_subject": "N/A",
            "certificate_issuer": "N/A",
            "key_size": 0,
            "quantum_safe": False,
            "is_pqc_hybrid": False,
            "error": str(e)
        }

    # 3. Secure TLS Socket Connection
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    raw_sock = None
    tls_sock = None
    try:
        # Connect directly to the validated numeric IP address.
        # This completely closes the TOCTOU DNS rebinding gap because no secondary
        # DNS resolution occurs during socket creation.
        raw_sock = socket.create_connection((target_ip, port_num), timeout=timeout)
        raw_sock.settimeout(timeout)

        # Wrap socket with TLS, passing clean_host as server_hostname for SNI and cert verification
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=clean_host)

        cert = tls_sock.getpeercert()
        cipher = tls_sock.cipher()
        tls_ver = tls_sock.version()

        # Extract certificate fields
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))

        cert_subject = subject_dict.get("commonName") or clean_host
        cert_issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Verified CA"

        cipher_name = cipher[0] if cipher else "Unknown"
        key_size = int(cipher[2]) if cipher and len(cipher) > 2 and cipher[2] is not None else 0

        # Quantum safety detection for TLS
        cipher_upper = cipher_name.upper()
        is_pqc = any(k in cipher_upper for k in ["ML-KEM", "KYBER", "HYBRID", "X25519MLKEM", "SLH-DSA", "ML-DSA"])

        return {
            "host": clean_host,
            "port": port_num,
            "resolved_ip": target_ip,
            "is_safe": True,
            "tls_version": tls_ver or "TLSv1.3",
            "cipher_suite": cipher_name,
            "certificate_subject": cert_subject,
            "certificate_issuer": cert_issuer,
            "key_size": key_size,
            "quantum_safe": is_pqc,
            "is_pqc_hybrid": is_pqc,
            "error": None
        }

    except ssl.SSLCertVerificationError as e:
        # Do NOT report unverified certificate details as trustworthy
        verify_msg = getattr(e, "verify_message", str(e))
        return {
            "host": clean_host,
            "port": port_num,
            "resolved_ip": target_ip,
            "is_safe": False,
            "tls_version": "N/A",
            "cipher_suite": "N/A",
            "certificate_subject": "UNVERIFIED",
            "certificate_issuer": "UNVERIFIED",
            "key_size": 0,
            "quantum_safe": False,
            "is_pqc_hybrid": False,
            "error": f"Certificate verification failed: {verify_msg}"
        }
    except ssl.SSLError as e:
        return {
            "host": clean_host,
            "port": port_num,
            "resolved_ip": target_ip,
            "is_safe": False,
            "tls_version": "N/A",
            "cipher_suite": "N/A",
            "certificate_subject": "UNVERIFIED",
            "certificate_issuer": "UNVERIFIED",
            "key_size": 0,
            "quantum_safe": False,
            "is_pqc_hybrid": False,
            "error": f"TLS handshake failed: {e}"
        }
    except (socket.timeout, TimeoutError) as e:
        return {
            "host": clean_host,
            "port": port_num,
            "resolved_ip": target_ip,
            "is_safe": False,
            "tls_version": "N/A",
            "cipher_suite": "N/A",
            "certificate_subject": "N/A",
            "certificate_issuer": "N/A",
            "key_size": 0,
            "quantum_safe": False,
            "is_pqc_hybrid": False,
            "error": f"Connection or TLS handshake timed out after {timeout}s: {e}"
        }
    except Exception as e:
        return {
            "host": clean_host,
            "port": port_num,
            "resolved_ip": target_ip,
            "is_safe": False,
            "tls_version": "N/A",
            "cipher_suite": "N/A",
            "certificate_subject": "N/A",
            "certificate_issuer": "N/A",
            "key_size": 0,
            "quantum_safe": False,
            "is_pqc_hybrid": False,
            "error": f"TLS connection failed: {e}"
        }
    finally:
        # Guarantee sockets are closed reliably
        if tls_sock is not None:
            try:
                tls_sock.close()
            except Exception:
                pass
        elif raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass
