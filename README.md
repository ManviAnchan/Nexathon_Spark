# Keynova: Autonomous Post-Quantum Cryptographic Readiness Platform

[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL_16-blue?logo=postgresql)](docker-compose.yml)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](backend/)
[![React](https://img.shields.io/badge/Frontend-React_19_+_Vite-61DAFB?logo=react)](frontend/)
[![Tests](https://img.shields.io/badge/Tests-160%20Passed-brightgreen)](backend/tests/)
[![NIST](https://img.shields.io/badge/Standards-FIPS%20203%20%7C%20204-purple)](https://csrc.nist.gov/pqc)
[![License](https://img.shields.io/badge/Security-Air--Gapped_Local--First-emerald)](README.md)

**Keynova** is an enterprise-grade, local-first post-quantum cryptographic (PQC) discovery, scoring, and remediation platform. It identifies classical cryptographic debt across source code and dependencies, detects **Harvest-Now-Decrypt-Later (HNDL)** exposure, and automates modernization to **NIST standardized algorithms (FIPS 203 ML-KEM & FIPS 204 ML-DSA)**.

---

## 🌟 Core Capabilities

* **Multi-Vector AST Discovery:** Analyzes source code using in-memory Python Abstract Syntax Trees (`ast`), traversing import aliases across module boundaries, tracking function calls, and extracting exact key bit lengths.
* **Harvest-Now-Decrypt-Later (HNDL) Threat Detection:** Flags classical asymmetric key exchange mechanisms (RSA-2048, ECC SECP256R1) vulnerable to retroactive quantum decryption, applying a **1.4x penalty surcharge**.
* **Deterministic Keynova Readiness Index ($R$):**
  $$R = \text{round}\left( \max(0, 100 - D_{\text{risk}}) \times C \right)$$
  A mathematically bounded $0–100$ score factoring risk penalties, HNDL multipliers, confidence levels, and code coverage factor ($C$).
* **PQC Playground & Benchmarking:** Live microsecond ($\mu s$) execution benchmarks comparing classical primitives against NIST FIPS 203 (ML-KEM-768/1024) and FIPS 204 (ML-DSA-65).
* **AI-Guided Remediation Engine:** Evidence-grounded unified diff generator supporting local Ollama LLM inference with deterministic, zero-drop offline fallback.
* **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM):** Exports standardized machine-readable CBOM JSON mapping cryptographic assets, algorithms, and post-quantum replacement paths.
* **Executive PDF Audit Reports:** Automatically compiles multi-page executive security summaries with readiness gauges, risk breakdowns, and migration roadmaps.
* **Zero-Trust TLS Inspector:** Audits live domain TLS cipher suites and certificates with active **DNS rebinding defenses and SSRF shields** (blocking private, loopback, and metadata ranges).
* **CI/CD Security Policy Gates:** CLI policy engine evaluating repositories against enterprise criteria (`min_readiness_score`, `max_critical_findings`, `block_on_hndl`) with standard exit codes.
* **Zero-Egress Air-Gapped Architecture:** 100% local processing; source code never leaves the host machine.

---

## 🏗️ Architecture

```
Nexathon_Spark/
├── backend/
│   ├── keynova/
│   │   ├── api/v1/                # REST API Routers (Projects, Scans, Graph, Export, TLS, Playground, Remediation)
│   │   ├── cli/                   # CLI entry points and CI/CD policy gate engine
│   │   ├── core/                  # Configuration, SQLAlchemy dual-database engine, Pydantic DTOs
│   │   └── services/
│   │       ├── crypto/            # NIST microsecond benchmark harness
│   │       ├── exporters/         # CycloneDX 1.6 CBOM and ReportLab PDF generators
│   │       ├── ingestion/         # Safe Zip-Slip extractor & HTTPS Git cloner
│   │       ├── intelligence/      # Mathematical Readiness Index & scan diff comparator
│   │       ├── remediation/       # AI & deterministic PQC migration engine
│   │       ├── scanner/           # Python AST visitor and manifest parser
│   │       └── tls/               # Zero-trust TLS handshake & SSRF inspector
│   ├── tests/                     # Automated 160-test pytest suite
│   └── requirements.txt           # Backend dependencies
├── frontend/                      # React 19 + TypeScript + Vite 6 + Tailwind CSS v4
│   ├── src/
│   │   ├── components/            # Sidebar, UploadModal
│   │   ├── lib/                   # Typed API client with offline demo fallbacks
│   │   ├── screens/               # Dashboard, FindingsExplorer, Graph, Verification, Playground
│   │   └── types/                 # Strict TypeScript schemas
│   └── package.json
├── test-fixtures/                 # Packaged vulnerable & remediated test payment microservices
├── docker-compose.yml             # PostgreSQL 16 Alpine container
├── run_desktop.sh                 # Linux/macOS launcher script
└── run_desktop.bat                # Windows launcher script
```

---

## 🚀 Quickstart

### 1. Prerequisites
* **Docker & Docker Compose** (for PostgreSQL)
* **Python 3.11+**
* **Node.js v20+** and **npm**

### 2. Start PostgreSQL Database
```bash
docker compose up -d
```
*(Keynova also includes an automatic fallback to local SQLite `keynova.db` if PostgreSQL is not running).*

### 3. Start Backend API
```bash
# Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Start FastAPI server on loopback
PYTHONPATH=backend uvicorn keynova.main:app --host 127.0.0.1 --port 8000
```
* **API Documentation (Swagger UI):** [`http://127.0.0.1:8000/docs`](http://127.0.0.1:8000/docs)
* **Health Check:** [`http://127.0.0.1:8000/health`](http://127.0.0.1:8000/health)

### 4. Start Frontend
```bash
cd frontend
npm install
npm run dev
```
* **Web UI:** [`http://127.0.0.1:5173`](http://127.0.0.1:5173)

---

## 🧪 Automated Testing

Keynova includes a comprehensive 160-test automated verification suite covering security, parsing, and cryptographic correctness:

```bash
PYTHONPATH=backend pytest backend/tests/ -v
```

### Test Coverage Highlights
* `test_cbom.py`: CycloneDX 1.6 schema adherence and component dependency mappings.
* `test_pdf.py`: Multi-page layout synthesis, XML escaping, and score tier badges.
* `test_tls.py`: SSRF validation, IPv4/IPv6 private range shielding, and certificate extraction.
* `test_cli_policy.py`: Policy evaluation gates and CLI compliance thresholds.
* `test_scoring_and_diff.py`: Bounded mathematical invariants ($0 \le R \le 100$) and scan diffing.
* `test_ai_crypto.py`: NIST benchmark execution and Ollama provider fallbacks.
* `test_api_integration.py` & `test_ingestion_and_ast.py`: REST routes and Zip-Slip AST extraction.

---

## 💻 CLI & CI/CD Policy Gates

Evaluate codebases directly in terminal or CI/CD pipelines:

```bash
# Scan a repository and evaluate against security policy
PYTHONPATH=backend python3 -m keynova.cli scan ./test-fixtures/vulnerable_payment_suite \
  --min-score 80 \
  --block-hndl \
  --export-cbom cbom.json \
  --export-pdf report.pdf
```

---

## 🔒 Security & Privacy Model

Keynova is engineered specifically for defense, financial, and air-gapped environments:
* **Loopback Exclusivity:** API binds strictly to `127.0.0.1:8000`.
* **Zero Egress:** No code, tokens, or telemetry leave the host machine.
* **Zip-Slip & Path Traversal Defense:** Canonical destination path checks (`os.path.commonpath`) on archives.
* **SSRF Shielding:** Prohibits private RFC 1918, loopback, link-local, and cloud metadata (`169.254.169.254`) requests.
* **In-Memory AST Parsing:** Code is parsed into Python's native abstract syntax tree in-memory without remote compilation.
