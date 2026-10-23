"""
Keynova CI/CD Cryptographic Readiness Scanner and Policy Evaluator.

Command-line interface for assessing repository cryptographic health,
evaliving policy constraints, and enforcing automated gating in CI/CD pipelines.

Exit Codes:
  0: Success / Policy check passed (zero violations).
  1: Policy violations detected (build failure).
  2: Usage, input, file-not-found, or evaluation parsing error.
"""

import sys
import argparse
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from keynova.services.scanner.python_ast import scan_python_file
from keynova.services.scanner.manifests import scan_manifest_file
from keynova.services.intelligence.scoring import calculate_readiness_score
from keynova.cli.policy import evaluate_policy, load_policy, DEFAULT_POLICY


def load_findings_from_file(file_path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Loads findings and optional scan metadata from a JSON file.
    Supports raw list of findings, scan report objects, or CycloneDX CBOM files.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Findings file '{file_path}' does not exist.")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Malformed JSON in findings file '{file_path}': {e}")
    except Exception as e:
        raise ValueError(f"Failed to read findings file '{file_path}': {e}")

    if isinstance(data, list):
        return data, {}
    elif isinstance(data, dict):
        if "findings" in data and isinstance(data["findings"], list):
            meta = {k: v for k, v in data.items() if k != "findings"}
            return data["findings"], meta
        # Support CycloneDX CBOM with components
        elif "components" in data and isinstance(data["components"], list):
            findings = []
            for comp in data["components"]:
                crypto = comp.get("cryptoProperties", {})
                algo_props = crypto.get("algorithmProperties", {})
                findings.append({
                    "id": comp.get("bom-ref", ""),
                    "algorithm": comp.get("name", ""),
                    "usage": algo_props.get("primitive", ""),
                    "severity": "critical" if algo_props.get("cryptoFunctions") else "medium",
                    "hndl": False
                })
            return findings, {}
        else:
            raise ValueError("JSON file must be an array of findings or an object containing a 'findings' list.")
    else:
        raise ValueError("Invalid findings JSON format: root must be a list or object.")


def scan_directory(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Scans a local repository directory using AST and manifest scanners.
    Calculates the Keynova Readiness Index.
    """
    if not root.exists():
        raise FileNotFoundError(f"Target path '{root}' does not exist.")
    if not root.is_dir():
        raise NotADirectoryError(f"Target path '{root}' is not a directory.")

    all_files = []
    scanned_files = []
    findings = []

    for p in root.rglob("*"):
        if any(part in [".git", "node_modules", ".venv", "__pycache__"] for part in p.parts):
            continue
        if p.is_file():
            all_files.append(p)
            if p.suffix == ".py":
                scanned_files.append(p)
                findings.extend([f.to_dict() for f in scan_python_file(p, relative_to=root)])
            elif p.name.lower() in ["requirements.txt", "package.json"]:
                scanned_files.append(p)
                findings.extend(scan_manifest_file(p, relative_to=root))

    report = calculate_readiness_score(findings, len(all_files), len(scanned_files))
    return findings, report


def build_parser() -> argparse.ArgumentParser:
    """Constructs the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="keynova-cli",
        description="KEYNOVA Cryptographic Post-Quantum Readiness Policy Evaluator"
    )
    # Positional target directory or findings file
    parser.add_argument(
        "target_dir",
        nargs="?",
        default=None,
        type=str,
        help="Target repository directory to scan, or path to a findings JSON file."
    )
    # Explicit findings input file
    parser.add_argument(
        "--findings", "-f",
        type=str,
        default=None,
        help="Path to an existing findings JSON file to evaluate."
    )
    # Policy configuration file
    parser.add_argument(
        "--policy", "-p",
        type=str,
        default=None,
        help="Path to custom policy JSON configuration file."
    )
    # Policy rule overrides
    parser.add_argument(
        "--min-readiness",
        type=int,
        default=80,
        help="Minimum acceptable Keynova Readiness Index (0-100, default: 80)."
    )
    parser.add_argument(
        "--block-hndl",
        action="store_true",
        default=True,
        help="Fail build if any Harvest-Now-Decrypt-Later (HNDL) risk is detected (default: True)."
    )
    parser.add_argument(
        "--no-block-hndl",
        dest="block_hndl",
        action="store_false",
        help="Do not fail build on Harvest-Now-Decrypt-Later (HNDL) risks."
    )
    parser.add_argument(
        "--max-severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Maximum permitted finding severity (findings exceeding this severity cause failure)."
    )
    parser.add_argument(
        "--disallow-algorithms",
        type=str,
        default="",
        help="Comma-separated list of prohibited algorithms (e.g. 'MD5,SHA-1,DES,3DES,RC4')."
    )
    parser.add_argument(
        "--require-quantum-safe",
        action="store_true",
        default=False,
        help="Strict policy: fail if any non-quantum-safe algorithm is found."
    )
    # Output formats
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output evaluation results as machine-readable JSON."
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="File path to write the evaluation JSON report."
    )
    return parser


def run_cli(args: Optional[List[str]] = None):
    """
    Main CLI entrypoint.
    Executes directory scanning or findings evaluation, evaluates policy rules,
    prints human-readable or JSON output, and terminates with appropriate exit code.
    """
    if args is None:
        raw_args = list(sys.argv[1:])
    else:
        raw_args = list(args)

    # Support optional 'scan' subcommand (e.g. `keynova-cli scan test-fixtures/...`)
    if raw_args and raw_args[0] == "scan":
        raw_args = raw_args[1:]

    parser = build_parser()
    parsed_args = parser.parse_args(raw_args)

    # 1. Determine input source
    findings_file = parsed_args.findings
    target_path_str = parsed_args.target_dir

    if not findings_file and not target_path_str:
        parser.print_help(sys.stderr)
        print("\n[ERROR] Either target_dir or --findings must be specified.", file=sys.stderr)
        sys.exit(2)

    # 2. Load findings and metadata
    findings: List[Dict[str, Any]] = []
    scan_meta: Dict[str, Any] = {}

    try:
        if findings_file:
            p = Path(findings_file).resolve()
            findings, scan_meta = load_findings_from_file(p)
        else:
            p = Path(target_path_str).resolve()
            if not p.exists():
                print(f"Error: Target path {p} does not exist.", file=sys.stderr)
                sys.exit(2)

            if p.is_file():
                # Provided a JSON findings file as positional argument
                findings, scan_meta = load_findings_from_file(p)
            else:
                # Provided a directory to scan
                if not parsed_args.json:
                    print(f"\n[SCAN] Analyzing repository: {p}")
                findings, scan_meta = scan_directory(p)

    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e}", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"[ERROR] Input error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"[ERROR] Failed to load scan targets: {e}", file=sys.stderr)
        sys.exit(2)

    # 3. Load and merge policy configuration
    try:
        policy = load_policy(parsed_args.policy)
    except (FileNotFoundError, ValueError, TypeError) as e:
        print(f"[ERROR] Policy configuration error: {e}", file=sys.stderr)
        sys.exit(2)

    # Apply CLI argument overrides
    policy["min_readiness_score"] = parsed_args.min_readiness
    policy["block_hndl"] = parsed_args.block_hndl
    if parsed_args.max_severity:
        policy["max_severity"] = parsed_args.max_severity
    if parsed_args.disallow_algorithms:
        cli_algos = [a.strip() for a in parsed_args.disallow_algorithms.split(",") if a.strip()]
        existing = policy.get("disallowed_algorithms", [])
        policy["disallowed_algorithms"] = list(set(existing + cli_algos))
    if parsed_args.require_quantum_safe:
        policy["require_quantum_safe"] = True

    # 4. Evaluate Policy
    result = evaluate_policy(findings=findings, policy=policy, scan_meta=scan_meta)

    # 5. Output handling
    if parsed_args.output:
        try:
            out_path = Path(parsed_args.output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            print(f"[ERROR] Failed to write output file: {e}", file=sys.stderr)
            sys.exit(2)

    if parsed_args.json:
        print(json.dumps(result, indent=2))
    else:
        # Human-readable terminal output
        score_disp = scan_meta.get("readiness_score", "N/A")
        cov_disp = scan_meta.get("coverage_percent", "100.0")
        hndl_disp = scan_meta.get("hndl_count", sum(1 for f in findings if f.get("hndl")))

        print("-" * 68)
        print(f"  Keynova Readiness Score: {score_disp} / 100")
        print(f"  Coverage:                {cov_disp}%")
        print(f"  Active Findings:         {len(findings)}")
        print(f"  HNDL Vulnerabilities:    {hndl_disp}")
        print("-" * 68)

        if not result["passed"]:
            print(f"\n[FAILED] CI/CD GATING FAILED: {len(result['violations'])} policy violation(s) detected:")
            for v in result["violations"]:
                loc = f" ({v['file_path']}:{v['line']})" if v.get("file_path") and v.get("line") else ""
                print(f"  [ERROR] {v['message']}{loc}")
            print("\nBuild failed with exit code 1.\n")
        else:
            print("\n[PASSED] CI/CD GATING PASSED: Codebase meets post-quantum policy requirements.\n")

    # 6. Exit Code
    if result["passed"]:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    run_cli()
