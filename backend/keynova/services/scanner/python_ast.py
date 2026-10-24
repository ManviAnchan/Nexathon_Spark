import ast
import hashlib
from pathlib import Path
from typing import List, Dict, Any

class AstCryptoFinding:
    def __init__(
        self,
        file_path: str,
        line_start: int,
        line_end: int,
        code_snippet: str,
        asset_type: str,
        algorithm: str,
        usage: str,
        library: str,
        key_size: int,
        severity: str,
        quantum_status: str,
        hndl: bool,
        confidence: float,
        rule_id: str,
        evidence: str
    ):
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end
        self.code_snippet = code_snippet
        self.asset_type = asset_type
        self.algorithm = algorithm
        self.usage = usage
        self.library = library
        self.key_size = key_size
        self.severity = severity
        self.quantum_status = quantum_status
        self.hndl = hndl
        self.confidence = confidence
        self.rule_id = rule_id
        self.evidence = evidence
        self.fingerprint = self._calculate_fingerprint()

    def _calculate_fingerprint(self) -> str:
        raw = f"{self.file_path}:{self.algorithm}:{self.usage}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "asset_type": self.asset_type,
            "algorithm": self.algorithm,
            "usage": self.usage,
            "library": self.library,
            "key_size": self.key_size,
            "severity": self.severity,
            "quantum_status": self.quantum_status,
            "hndl": self.hndl,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AstCryptoFinding":
        return cls(
            file_path=data.get("file_path", ""),
            line_start=data.get("line_start", 1),
            line_end=data.get("line_end", 1),
            code_snippet=data.get("code_snippet", ""),
            asset_type=data.get("asset_type", "source_code"),
            algorithm=data.get("algorithm", "Unknown"),
            usage=data.get("usage", "encryption"),
            library=data.get("library", ""),
            key_size=data.get("key_size", 0),
            severity=data.get("severity", "low"),
            quantum_status=data.get("quantum_status", "quantum_vulnerable"),
            hndl=data.get("hndl", False),
            confidence=data.get("confidence", 1.0),
            rule_id=data.get("rule_id", "UNKNOWN"),
            evidence=data.get("evidence", "")
        )

class CryptoAstVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.lines = source_code.splitlines()
        self.findings: List[AstCryptoFinding] = []
        
        # Track aliased module and function imports
        # e.g., 'legacy_rsa': 'cryptography.rsa'
        self.aliases: Dict[str, str] = {}

    def _get_snippet(self, node: ast.AST) -> str:
        start = max(1, getattr(node, "lineno", 1)) - 1
        end = getattr(node, "end_lineno", start + 1)
        return "\n".join(self.lines[start:end]).strip()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            as_name = alias.asname or alias.name
            self.aliases[as_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            as_name = alias.asname or alias.name
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.aliases[as_name] = full_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        full_qual = ""

        # Resolving call target (e.g. legacy_rsa.generate_private_key)
        if isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                target_obj = node.func.value.id
                resolved_base = self.aliases.get(target_obj, target_obj)
                full_qual = f"{resolved_base}.{attr_name}"
                func_name = attr_name
            elif isinstance(node.func.value, ast.Attribute):
                # multi-level attribute e.g. hashlib.md5
                func_name = attr_name
                full_qual = f"{ast.unparse(node.func.value)}.{attr_name}"
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            full_qual = self.aliases.get(func_name, func_name)

        # 1. RSA Key Generation (Critical / HNDL)
        if "rsa" in full_qual.lower() and "generate_private_key" in func_name:
            key_size = 2048
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    key_size = int(kw.value.value)

            snippet = self._get_snippet(node)
            self.findings.append(AstCryptoFinding(
                file_path=self.file_path,
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
                code_snippet=snippet,
                asset_type="source_code",
                algorithm="RSA",
                usage="key_generation",
                library="cryptography",
                key_size=key_size,
                severity="critical",
                quantum_status="quantum_vulnerable",
                hndl=True,
                confidence=0.95,
                rule_id="PYTHON_RSA_KEYGEN",
                evidence=f"RSA-{key_size} key establishment is vulnerable to Shor's algorithm. Attackers can harvest ciphertext today to decrypt in the future."
            ))

        # 2. ECC Key Generation / ECDSA (High / Quantum Vulnerable)
        elif "generate_private_key" in func_name and ("ec" in full_qual or "elliptic_curve" in full_qual):
            snippet = self._get_snippet(node)
            self.findings.append(AstCryptoFinding(
                file_path=self.file_path,
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
                code_snippet=snippet,
                asset_type="source_code",
                algorithm="ECC-SECP256R1",
                usage="token_signing",
                library="cryptography",
                key_size=256,
                severity="high",
                quantum_status="quantum_vulnerable",
                hndl=True,
                confidence=0.90,
                rule_id="PYTHON_ECC_SECP256R1",
                evidence="Elliptic Curve Cryptography (SECP256R1) discrete logarithm problem is breakable by Shor's algorithm on quantum hardware."
            ))

        # 3. MD5 Hashing (Low / Classical Weakness)
        elif "md5" in full_qual.lower() or "hashlib.md5" in full_qual:
            snippet = self._get_snippet(node)
            self.findings.append(AstCryptoFinding(
                file_path=self.file_path,
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
                code_snippet=snippet,
                asset_type="source_code",
                algorithm="MD5",
                usage="password_hashing",
                library="hashlib",
                key_size=128,
                severity="low",
                quantum_status="classical_weakness",
                hndl=False,
                confidence=1.0,
                rule_id="PYTHON_MD5_HASH",
                evidence="MD5 suffers from known collision attacks and classical preimage vulnerabilities; recommend SHA-3 or BLAKE2."
            ))

        # 4. SHA-1 Hashing (Low / Classical Weakness)
        elif "sha1" in full_qual.lower() or "hashlib.sha1" in full_qual:
            snippet = self._get_snippet(node)
            self.findings.append(AstCryptoFinding(
                file_path=self.file_path,
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
                code_snippet=snippet,
                asset_type="source_code",
                algorithm="SHA-1",
                usage="hashing",
                library="hashlib",
                key_size=160,
                severity="low",
                quantum_status="classical_weakness",
                hndl=False,
                confidence=1.0,
                rule_id="PYTHON_SHA1_HASH",
                evidence="SHA-1 collision resistance is broken; replace with SHA-256 or SHA-3."
            ))

        self.generic_visit(node)

def scan_python_file(file_path: Path, relative_to: Path, use_cache: bool = True) -> List[AstCryptoFinding]:
    """Parses a Python file using AST and returns crypto findings with content-addressable caching."""
    rel_path = str(file_path.relative_to(relative_to))
    try:
        content = file_path.read_text(encoding="utf-8")
        if use_cache:
            try:
                from keynova.services.cache.ast_cache import get_ast_cache
                cache = get_ast_cache()
                cached_data = cache.get(content)
                if cached_data is not None:
                    findings = []
                    for item in cached_data:
                        d = dict(item)
                        d["file_path"] = rel_path
                        findings.append(AstCryptoFinding.from_dict(d))
                    return findings
            except Exception:
                pass

        tree = ast.parse(content, filename=str(file_path))
        visitor = CryptoAstVisitor(rel_path, content)
        visitor.visit(tree)

        if use_cache:
            try:
                from keynova.services.cache.ast_cache import get_ast_cache
                cache = get_ast_cache()
                cache.set(content, [f.to_dict() for f in visitor.findings], file_path=rel_path)
            except Exception:
                pass

        return visitor.findings
    except SyntaxError:
        return []
    except Exception:
        return []
