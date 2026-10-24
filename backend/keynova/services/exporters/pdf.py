"""
Keynova Executive PDF Report Generator.

Generates an executive-ready cryptographic audit and post-quantum readiness
report in PDF format using ReportLab. Suitable for non-technical executives,
auditors, and hackathon presentations.

Includes:
- Multi-page SimpleDocTemplate with ReportNumberedCanvas ("Page X of Y" and running headers)
- Robust XML escaping via xml.sax.saxutils.escape so < and & in code snippets never crash ReportLab
- Page 1: Cover Page with Keynova branding, scan ID, visual Readiness Index score gauge, and risk tier badge
- Page 2: Executive Summary with HNDL threat overview, code coverage, and severity breakdown table
- Page 3+: Full Cryptographic Debt Inventory table (file path, line number, algorithm, severity, NIST standard recommendation)
"""

import io
import sys
import xml.sax.saxutils
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

REPORTLAB_AVAILABLE = True


class ReportNumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that dynamically calculates the total page count
    and renders consistent running headers and footers across all pages.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        getattr(self, "_startPage")()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_decorations(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#64748b"))

        page_num = getattr(self, "_pageNumber", 1)

        # Running Header (pages 2+)
        if page_num > 1:
            self.drawString(40, letter[1] - 28, "KEYNOVA EXECUTIVE POST-QUANTUM READINESS REPORT")
            self.drawRightString(letter[0] - 40, letter[1] - 28, "CONFIDENTIAL CRYPTOGRAPHIC AUDIT")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(40, letter[1] - 32, letter[0] - 40, letter[1] - 32)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(40, 34, letter[0] - 40, 34)
        self.setFont("Helvetica", 7.5)
        self.drawString(40, 22, "KEYNOVA — Autonomous Post-Quantum Migration Platform")
        self.drawRightString(letter[0] - 40, 22, f"Page {page_num} of {total_pages}")
        self.restoreState()


def _escape(val: Any, default: str = "") -> str:
    """
    Safely escapes strings for ReportLab Paragraph XML parsing using xml.sax.saxutils.escape.
    Guarantees that < and & in code snippets and filenames never crash ReportLab.
    """
    if val is None:
        return default
    text = str(val).strip()
    return xml.sax.saxutils.escape(text) if text else default


def _classify_quantum_status(algo: str, explicit_status: Optional[str] = None) -> str:
    """Classifies an algorithm into 'safe', 'vulnerable', or 'unknown'."""
    if explicit_status:
        norm = explicit_status.lower().strip()
        if norm in ["safe", "quantum_safe", "quantum_resistant", "quantum-safe", "post_quantum"]:
            return "safe"
        if norm in ["vulnerable", "quantum_vulnerable", "broken"]:
            return "vulnerable"

    algo_lower = algo.lower().strip()
    pqc_tokens = [
        "ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "falcon",
        "sphincs", "xmss", "lms", "sha-3", "sha3", "shake", "aes-256", "chacha20"
    ]
    if any(tok in algo_lower for tok in pqc_tokens):
        return "safe"

    vuln_tokens = [
        "rsa", "ec", "ecdsa", "ecdh", "ed25519", "x25519", "curve25519",
        "dsa", "dh", "diffie-hellman", "secp", "md5", "sha-1", "sha1",
        "des", "3des", "rc4", "blowfish", "aes-128"
    ]
    if any(tok in algo_lower for tok in vuln_tokens):
        return "vulnerable"

    return "unknown"


def _analyze_risk_and_remediation(finding: Dict[str, Any]) -> Tuple[str, str]:
    """
    Derives plain-English risk explanation and standards-backed remediation
    based on the finding's cryptographic properties.
    """
    algo = str(finding.get("algorithm") or "").strip()
    algo_lower = algo.lower()
    usage = str(finding.get("usage") or "").strip().lower()
    is_hndl = bool(finding.get("hndl"))
    explicit_rec = finding.get("recommendation")

    # If explicit recommendation provided in finding, prioritize it
    remediation = str(explicit_rec).strip() if explicit_rec else ""

    # 1. Active Harvest-Now-Decrypt-Later or Asymmetric Key Encapsulation/Exchange
    if is_hndl or any(k in algo_lower for k in ["ecdh", "dh", "x25519"]) or ("rsa" in algo_lower and any(u in usage for u in ["encrypt", "key", "kem", "exchange"])):
        risk = "Vulnerable to Shor's algorithm. Active Harvest-Now-Decrypt-Later (HNDL) exposure: encrypted traffic can be recorded today and decrypted once quantum computers mature."
        if not remediation:
            remediation = "Migrate to NIST FIPS 203 (ML-KEM-768 / ML-KEM-1024) hybrid key encapsulation."
        return risk, remediation

    # 2. Digital Signatures / Authentication (RSA, ECDSA, Ed25519, DSA)
    if any(k in algo_lower for k in ["ecdsa", "ed25519", "dsa"]) or ("rsa" in algo_lower and any(u in usage for u in ["sign", "auth", "token", "cert", "verify"])):
        risk = "Vulnerable to quantum signature forgery via Shor's algorithm. Compromises digital signatures, non-repudiation, and token authenticity."
        if not remediation:
            remediation = "Migrate to NIST FIPS 204 (ML-DSA-65) or NIST FIPS 205 (SLH-DSA)."
        return risk, remediation

    # 3. General RSA
    if "rsa" in algo_lower:
        risk = "Classical public-key primitive vulnerable to Shor's algorithm polynomial-time prime factorization."
        if not remediation:
            remediation = "Migrate to NIST FIPS 203 (ML-KEM-768) for encryption or FIPS 204 (ML-DSA-65) for signatures."
        return risk, remediation

    # 4. Broken Legacy Hashes (MD5, SHA-1)
    if any(k in algo_lower for k in ["md5", "sha-1", "sha1"]):
        risk = "Legacy hash algorithm with practical classical collision attacks; breaks cryptographic hash integrity and signature security."
        if not remediation:
            remediation = "Upgrade to SHA-256 or NIST FIPS 202 (SHA-3-256 / SHA-3-512)."
        return risk, remediation

    # 5. Broken Legacy Ciphers (DES, 3DES, RC4, Blowfish)
    if any(k in algo_lower for k in ["des", "3des", "rc4", "blowfish"]):
        risk = "Obsolete legacy symmetric cipher vulnerable to classical cryptanalysis, short block sizes (Sweet32), or small key lengths."
        if not remediation:
            remediation = "Upgrade to AES-256-GCM authenticated symmetric encryption."
        return risk, remediation

    # 6. AES-128
    if "aes-128" in algo_lower:
        risk = "Grover's quantum search reduces effective symmetric key strength from 128 to ~64 bits against quantum brute-force attacks."
        if not remediation:
            remediation = "Upgrade to AES-256-GCM for >=128-bit quantum security strength."
        return risk, remediation

    # 7. Quantum-Safe primitives
    if _classify_quantum_status(algo, finding.get("quantum_status")) == "safe":
        risk = "Quantum-resilient algorithm aligned with current NIST post-quantum cryptographic standards."
        if not remediation:
            remediation = "Maintain current parameter set; monitor ongoing NIST and ENISA guidelines."
        return risk, remediation

    # 8. Fallback
    risk = "Cryptographic primitive requiring verification against quantum-resilient security policies."
    if not remediation:
        remediation = "Inspect usage parameters and align with NIST post-quantum migration standards."
    return risk, remediation


def generate_pdf_report(
    project_name: Optional[str] = None,
    scan_meta: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None
) -> bytes:
    """
    Generates an executive-ready multi-page Post-Quantum Cryptographic Readiness PDF report.

    Args:
        project_name: Name of the audited project or repository.
        scan_meta: Metadata dictionary containing readiness_score, coverage_percent,
                   scanned_files, total_files, hndl_count, id, etc.
        findings: List of finding dictionaries with algorithm, severity, file_path,
                  line_start, hndl, usage, etc.

    Returns:
        bytes: Generated PDF document starting with b'%PDF-'.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError(
            "ReportLab is required for PDF generation. Please install reportlab>=4.0.0."
        )

    if scan_meta is None:
        scan_meta = {}
    if findings is None:
        findings = []

    clean_project_name = project_name.strip() if project_name and project_name.strip() else "Cryptographic Service"
    scan_id = str(scan_meta.get("id") or "").strip()
    if not scan_id:
        scan_id = "SCAN-LOCAL-01"

    now_utc = datetime.now(timezone.utc)
    date_str = now_utc.strftime("%B %d, %Y")
    timestamp_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Document setup (Letter: 612 x 792 pt, margins 40pt -> 532pt usable width)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=46,
        bottomMargin=46
    )

    # Color Palette
    c_primary = colors.HexColor("#0f172a")   # Slate 900
    c_accent = colors.HexColor("#2563eb")    # Blue 600
    c_danger = colors.HexColor("#dc2626")    # Red 600
    c_warning = colors.HexColor("#d97706")   # Amber 600
    c_success = colors.HexColor("#059669")   # Emerald 600
    c_muted = colors.HexColor("#64748b")     # Slate 500
    c_dark = colors.HexColor("#1e293b")      # Slate 800
    c_card_bg = colors.HexColor("#f8fafc")   # Slate 50
    c_border = colors.HexColor("#cbd5e1")    # Slate 300

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'RepTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=c_primary,
        spaceAfter=3
    )
    subtitle_style = ParagraphStyle(
        'RepSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=c_muted,
        spaceAfter=6
    )
    h1_style = ParagraphStyle(
        'RepH1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=c_primary,
        spaceBefore=7,
        spaceAfter=3
    )
    body_style = ParagraphStyle(
        'RepBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11.5,
        textColor=c_dark
    )
    banner_style = ParagraphStyle(
        'RepBanner',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11.5,
        textColor=c_dark
    )
    roadmap_style = ParagraphStyle(
        'RepRoadmap',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11.5,
        textColor=c_dark
    )
    cell_style = ParagraphStyle(
        'RepCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=9.5,
        textColor=c_dark
    )
    table_header = ParagraphStyle(
        'RepHdr',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white
    )

    story = []

    # =========================================================================
    # COMPUTE METRICS & SCORE DATA
    # =========================================================================
    raw_score = scan_meta.get("readiness_score")
    if raw_score is not None:
        try:
            score = max(0, min(100, round(float(raw_score))))
            score_display = f"{score} / 100"
            if score < 50:
                score_color = "#dc2626"
                status_label = "CRITICAL RISK"
                score_interpretation = (
                    "High post-quantum cryptographic risk. The codebase relies heavily on vulnerable "
                    "classical public-key algorithms or active Harvest-Now-Decrypt-Later (HNDL) exposure "
                    "requiring urgent remediation before production deployment."
                )
            elif score < 80:
                score_color = "#d97706"
                status_label = "NEEDS UPGRADE"
                score_interpretation = (
                    "Moderate post-quantum cryptographic risk. Classical public-key cryptography or legacy "
                    "algorithms were identified without immediate critical exposure. A planned transition "
                    "to NIST FIPS 203/204 quantum-resilient standards is recommended."
                )
            else:
                score_color = "#059669"
                status_label = "QUANTUM READY"
                score_interpretation = (
                    "Strong post-quantum cryptographic readiness. The assessed codebase adheres closely to "
                    "NIST FIPS 203/204/205 post-quantum standards with high coverage and minimal risk exposure."
                )
        except (ValueError, TypeError):
            score = None
            score_display = "N/A"
            score_color = "#64748b"
            status_label = "UNASSESSED"
            score_interpretation = "Readiness score could not be calculated from the provided score format."
    else:
        score = None
        score_display = "N/A"
        score_color = "#64748b"
        status_label = "UNASSESSED"
        score_interpretation = (
            "Cryptographic readiness score was not computed for this scan. Review finding counts and file "
            "coverage to assess overall exposure."
        )

    # Extract scan coverage and file numbers safely
    raw_coverage = scan_meta.get("coverage_percent")
    coverage_str = f"{float(raw_coverage):.1f}%" if raw_coverage is not None else "100.0%"
    scanned_files = scan_meta.get("scanned_files")
    total_files = scan_meta.get("total_files")
    if scanned_files is not None and total_files is not None:
        files_str = f"{scanned_files} / {total_files}"
    else:
        files_str = "Not reported"

    # Compute finding metrics from source data
    total_findings = len(findings)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
    hndl_count = 0
    quantum_vuln_count = 0
    quantum_safe_count = 0

    for f in findings:
        sev = str(f.get("severity") or "low").strip().lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        elif sev in ["quantum_safe", "safe"]:
            sev_counts["safe"] += 1
        else:
            sev_counts["low"] += 1

        is_hndl = bool(f.get("hndl"))
        if is_hndl:
            hndl_count += 1

        q_status = _classify_quantum_status(str(f.get("algorithm") or ""), f.get("quantum_status"))
        if q_status == "safe":
            quantum_safe_count += 1
        elif q_status == "vulnerable":
            quantum_vuln_count += 1

    # Overwrite hndl_count from scan_meta if explicitly provided and findings are empty
    if "hndl_count" in scan_meta and scan_meta.get("hndl_count") is not None and hndl_count == 0:
        hndl_count = int(scan_meta.get("hndl_count"))

    # Top Risks Narrative
    if total_findings == 0:
        risk_summary = "<b>Zero Cryptographic Vulnerabilities Detected:</b> No legacy public-key algorithms or deprecated cryptographic primitives were identified in the scanned codebase."
    else:
        risk_bullets = []
        if hndl_count > 0:
            risk_bullets.append(f"<b>Harvest-Now-Decrypt-Later (HNDL):</b> <b>{hndl_count}</b> active key exchange vulnerability(ies) expose confidential traffic to retrospective quantum decryption.")
        if sev_counts["critical"] > 0:
            risk_bullets.append(f"<b>Critical Exposure:</b> <b>{sev_counts['critical']}</b> critical severity finding(s) requiring immediate engineering intervention.")
        if sev_counts["high"] > 0:
            risk_bullets.append(f"<b>High Exposure:</b> <b>{sev_counts['high']}</b> high severity finding(s) in authentication or signature primitives.")
        if quantum_vuln_count > 0 and hndl_count == 0 and sev_counts["critical"] == 0:
            risk_bullets.append(f"<b>Quantum-Vulnerable Primitives:</b> <b>{quantum_vuln_count}</b> classical primitive(s) requiring scheduled migration.")
        risk_summary = "<br/>".join(risk_bullets) if risk_bullets else "Low-severity observations noted; routine cryptographic hygiene recommended."

    # =========================================================================
    # PAGE 1: COVER PAGE
    # =========================================================================
    # =========================================================================
    # PAGE 1: EXECUTIVE POSTURE DASHBOARD
    # =========================================================================
    story.append(Paragraph("<font size='9.5' color='#2563eb'><b>KEYNOVA PLATFORM</b></font>", ParagraphStyle('Brand', parent=styles['Normal'], spaceAfter=3)))
    story.append(Paragraph("Executive Post-Quantum Cryptographic Audit Report", title_style))
    story.append(Paragraph(
        f"Target Repository: <b>{_escape(clean_project_name)}</b><br/>"
        f"Scan Identifier: <code>{_escape(scan_id)}</code><br/>"
        f"Audit Date: {_escape(date_str)} ({_escape(timestamp_str)})",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceBefore=2, spaceAfter=8))

    # Readiness Index score gauge
    p_gauge_title = Paragraph(
        "<b>KEYNOVA READINESS INDEX (R)</b>",
        ParagraphStyle(
            'ScoreTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11,
            alignment=1,
            textColor=colors.HexColor('#64748b')
        )
    )
    p_gauge_score = Paragraph(
        f"<b>{score_display}</b>",
        ParagraphStyle(
            'ScoreDisplay',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=30,
            leading=34,
            alignment=1,
            textColor=colors.HexColor(score_color)
        )
    )
    p_gauge_badge = Paragraph(
        f"<b>[{status_label}]</b>",
        ParagraphStyle(
            'ScoreBadge',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9.5,
            leading=12,
            alignment=1,
            textColor=colors.HexColor(score_color)
        )
    )
    p_gauge_details = Paragraph(
        f"<b>Executive Posture:</b> {score_interpretation}<br/>"
        f"<b>Active HNDL Exposures:</b> <font color='{c_danger.hexval()}'><b>{hndl_count}</b></font> | "
        f"<b>Audit Coverage:</b> {coverage_str} ({files_str} files scanned)",
        body_style
    )

    gauge_table_data = [
        [p_gauge_title],
        [p_gauge_score],
        [p_gauge_badge],
        [p_gauge_details]
    ]
    t_cover_gauge = Table(gauge_table_data, colWidths=[532])
    t_cover_gauge.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor(score_color)),
        ('LINEBELOW', (0, 2), (-1, 2), 0.5, c_border),
        ('ALIGN', (0, 0), (-1, 2), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 3),
        ('TOPPADDING', (0, 1), (-1, 1), 2),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 4),
        ('TOPPADDING', (0, 2), (-1, 2), 2),
        ('BOTTOMPADDING', (0, 2), (-1, 2), 8),
        ('PADDING', (0, 3), (-1, 3), 7),
    ]))
    story.append(t_cover_gauge)
    story.append(Spacer(1, 6))

    # Section 1: Threat Landscape & Security Posture Overview
    story.append(Paragraph("1. Threat Landscape & Security Posture Overview", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=5))

    banner_left = Paragraph(
        f"<b>Readiness Score:</b> <font color='{score_color}'><b>{score_display}</b></font><br/>"
        f"<b>Risk Posture:</b> <font color='{score_color}'><b>{status_label}</b></font><br/>"
        f"<b>Audit Coverage:</b> {coverage_str} ({files_str} files)",
        banner_style
    )
    banner_right = Paragraph(
        f"<b>HNDL Exposures:</b> <font color='{c_danger.hexval()}'><b>{hndl_count} detected</b></font><br/>"
        f"<b>Quantum-Vulnerable Assets:</b> <font color='{c_danger.hexval()}'><b>{quantum_vuln_count}</b></font><br/>"
        f"<b>Quantum-Safe Assets:</b> <font color='{c_success.hexval()}'><b>{quantum_safe_count}</b></font>",
        banner_style
    )
    banner_summary = Paragraph(f"<b>Key Threat Assessment:</b> {risk_summary}", banner_style)

    banner_data = [
        [banner_left, banner_right],
        [banner_summary, ""]
    ]
    t_banner = Table(banner_data, colWidths=[266, 266])
    t_banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(score_color)),
        ('SPAN', (0, 1), (1, 1)),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, 0), 0.5, c_border),
    ]))
    story.append(t_banner)
    story.append(Spacer(1, 6))

    # Severity Breakdown KPI Cards
    story.append(Paragraph("<b>Cryptographic Asset Severity Breakdown</b>", ParagraphStyle('Sub', parent=h1_style, fontSize=9, spaceBefore=2, spaceAfter=2)))
    summary_cards_data = [
        [
            Paragraph(f"<font size='12' color='{c_primary.hexval()}'><b>{total_findings}</b></font><br/><font size='6.5' color='#64748b'><b>TOTAL ASSETS</b></font>", ParagraphStyle('C1', parent=body_style, alignment=1, leading=11)),
            Paragraph(f"<font size='12' color='{c_danger.hexval()}'><b>{sev_counts['critical']}</b></font><br/><font size='6.5' color='#64748b'><b>CRITICAL</b></font>", ParagraphStyle('C2', parent=body_style, alignment=1, leading=11)),
            Paragraph(f"<font size='12' color='#ea580c'><b>{sev_counts['high']}</b></font><br/><font size='6.5' color='#64748b'><b>HIGH</b></font>", ParagraphStyle('C3', parent=body_style, alignment=1, leading=11)),
            Paragraph(f"<font size='12' color='{c_warning.hexval()}'><b>{sev_counts['medium']}</b></font><br/><font size='6.5' color='#64748b'><b>MEDIUM</b></font>", ParagraphStyle('C4', parent=body_style, alignment=1, leading=11)),
            Paragraph(f"<font size='12' color='{c_muted.hexval()}'><b>{sev_counts['low']}</b></font><br/><font size='6.5' color='#64748b'><b>LOW</b></font>", ParagraphStyle('C5', parent=body_style, alignment=1, leading=11)),
        ]
    ]
    t_summary = Table(summary_cards_data, colWidths=[106, 106, 106, 107, 107])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, 0), 0.5, c_border),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 6))

    # NIST Compliance Notice / Seal
    cover_seal = [
        [
            Paragraph(
                "<b>NIST Post-Quantum Cryptography Compliance Notice</b><br/>"
                "This assessment evaluates cryptographic posture against NIST FIPS 203 (ML-KEM), "
                "FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) post-quantum cryptographic standards. "
                "Static AST analysis and manifest inspection identify classical algorithms vulnerable "
                "to Shor's and Grover's quantum algorithms.",
                ParagraphStyle('Seal', parent=body_style, fontSize=7.5, leading=10)
            )
        ]
    ]
    t_cover_seal = Table(cover_seal, colWidths=[532])
    t_cover_seal.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#93c5fd")),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_cover_seal)

    # Page Break after executive dashboard
    story.append(PageBreak())

    # =========================================================================
    # PAGE 2+: REMEDIATION ROADMAP, INVENTORY & AUDIT SCOPE
    # =========================================================================
    story.append(Paragraph("2. Strategic NIST Remediation Roadmap", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=5))

    has_hndl_or_kem = any(
        bool(f.get("hndl")) or any(k in str(f.get("algorithm") or "").lower() for k in ["ecdh", "dh", "x25519"]) or
        ("rsa" in str(f.get("algorithm") or "").lower() and any(u in str(f.get("usage") or "").lower() for u in ["encrypt", "key", "kem", "exchange"]))
        for f in findings
    )
    has_signatures = any(
        any(k in str(f.get("algorithm") or "").lower() for k in ["ecdsa", "ed25519", "dsa"]) or
        ("rsa" in str(f.get("algorithm") or "").lower() and any(u in str(f.get("usage") or "").lower() for u in ["sign", "auth", "token", "cert", "verify"]))
        for f in findings
    )
    has_legacy_hash_or_cipher = any(
        any(k in str(f.get("algorithm") or "").lower() for k in ["md5", "sha-1", "sha1", "des", "3des", "rc4", "blowfish"])
        for f in findings
    )

    priority_items = []
    if total_findings == 0:
        priority_items.append(
            "• <b>Continuous Compliance:</b> Maintain cryptographic agility across software dependencies. "
            "Automate continuous Cryptographic Bill of Materials (CBOM) generation in CI/CD pipelines to guarantee "
            "no unvetted classical primitives are reintroduced."
        )
    else:
        p_num = 1
        if has_hndl_or_kem:
            priority_items.append(
                f"• <b>Priority {p_num} (Urgent — HNDL Mitigation):</b> Halt Harvest-Now-Decrypt-Later leakage by deprecating "
                f"classical RSA and elliptic-curve key exchanges. Deploy hybrid or pure post-quantum key encapsulation "
                f"mechanisms compliant with <b>NIST FIPS 203 (ML-KEM-768 / ML-KEM-1024)</b>."
            )
            p_num += 1

        if has_signatures:
            priority_items.append(
                f"• <b>Priority {p_num} (High — Authentication & Signatures):</b> Transition digital signature schemes, API tokens, "
                f"and certificate authorities to quantum-resilient lattice-based signatures conforming to <b>NIST FIPS 204 (ML-DSA-65)</b> "
                f"or state-less hash signatures <b>NIST FIPS 205 (SLH-DSA)</b>."
            )
            p_num += 1

        if has_legacy_hash_or_cipher:
            priority_items.append(
                f"• <b>Priority {p_num} (Medium — Legacy Primitives):</b> Eliminate broken collision-vulnerable hashes (MD5, SHA-1) "
                f"and obsolete symmetric ciphers. Upgrade to <b>SHA-256</b> or <b>NIST FIPS 202 (SHA-3)</b> and <b>AES-256-GCM</b>."
            )
            p_num += 1

        priority_items.append(
            f"• <b>Priority {p_num} (Agility Assurance):</b> Establish automated CBOM verification as a gating check in pull requests "
            f"to monitor dependency manifests and crypto-asset compliance against updated NIST migration deadlines."
        )

    priorities_text = "<br/><br/>".join(priority_items)
    t_priorities = Table([[Paragraph(priorities_text, roadmap_style)]], colWidths=[532])
    t_priorities.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#93c5fd")),
        ('PADDING', (0, 0), (-1, -1), 6)
    ]))
    story.append(t_priorities)
    story.append(Spacer(1, 8))

    # Full Cryptographic Debt Inventory
    story.append(Paragraph("3. Full Cryptographic Debt Inventory", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=4))

    findings_rows = [
        [
            Paragraph("File Path & Location", table_header),
            Paragraph("Detected Algorithm", table_header),
            Paragraph("Severity", table_header),
            Paragraph("HNDL", table_header),
            Paragraph("Risk Explanation", table_header),
            Paragraph("NIST Recommendation", table_header)
        ]
    ]

    if total_findings == 0:
        findings_rows.append([
            Paragraph("<b>Zero vulnerabilities detected.</b> All audited codebase assets comply with NIST post-quantum security baselines (FIPS 203/204/205).", cell_style),
            Paragraph("", cell_style),
            Paragraph("", cell_style),
            Paragraph("", cell_style),
            Paragraph("", cell_style),
            Paragraph("", cell_style)
        ])
    else:
        for f in findings:
            file_path = _escape(f.get("file_path"), "Unknown file")
            line_start = f.get("line_start")
            line_end = f.get("line_end")
            if line_start is not None and line_end is not None and line_start != line_end:
                loc_str = f"<b>{file_path}</b><br/>Lines {line_start}-{line_end}"
            elif line_start is not None:
                loc_str = f"<b>{file_path}</b><br/>Line {line_start}"
            else:
                loc_str = f"<b>{file_path}</b><br/>Line N/A"

            algo = _escape(f.get("algorithm"), "Unknown")
            usage = _escape(f.get("usage"), "")
            key_size = f.get("key_size")
            algo_display = f"<b>{algo}</b>"
            if key_size:
                algo_display += f" ({key_size}-bit)"
            if usage:
                algo_display += f"<br/>{usage}"

            sev_raw = str(f.get("severity") or "low").strip().lower()
            if sev_raw == "critical":
                sev_color = "#dc2626"
            elif sev_raw == "high":
                sev_color = "#ea580c"
            elif sev_raw == "medium":
                sev_color = "#d97706"
            elif sev_raw in ["quantum_safe", "safe"]:
                sev_color = "#059669"
            else:
                sev_color = "#475569"
            sev_display = f"<b><font color='{sev_color}'>{sev_raw.upper()}</font></b>"

            is_hndl = bool(f.get("hndl"))
            hndl_display = f"<b><font color='#dc2626'>YES</font></b>" if is_hndl else "<font color='#64748b'>No</font>"

            risk_desc, remediation_desc = _analyze_risk_and_remediation(f)

            findings_rows.append([
                Paragraph(loc_str, cell_style),
                Paragraph(algo_display, cell_style),
                Paragraph(sev_display, cell_style),
                Paragraph(hndl_display, cell_style),
                Paragraph(_escape(risk_desc), cell_style),
                Paragraph(_escape(remediation_desc), cell_style)
            ])

    # Table ColWidths: 110 + 85 + 52 + 40 + 122 + 123 = 532
    t_findings = Table(findings_rows, colWidths=[110, 85, 52, 40, 122, 123], repeatRows=1)
    table_styles: List[Any] = [
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_card_bg]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 3.5),
    ]
    if total_findings == 0:
        table_styles.append(('SPAN', (0, 1), (-1, 1)))

    t_findings.setStyle(TableStyle(table_styles))
    story.append(t_findings)
    story.append(Spacer(1, 8))

    # Audit Scope & Methodological Limitations
    story.append(Paragraph("4. Scope & Methodological Limitations", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=4))

    limitations = []
    if raw_score is None:
        limitations.append("• <b>Readiness Score Notice:</b> A composite readiness score was not computed for this scan because readiness score metadata was omitted or unavailable.")
    else:
        limitations.append(f"• <b>Readiness Score Basis:</b> Keynova Readiness Index ({score_display}) was derived deterministically from finding risk penalties and coverage factors.")

    if raw_coverage is not None:
        cov_val = float(raw_coverage)
        if cov_val < 100.0:
            limitations.append(f"• <b>Partial Coverage:</b> Assessment achieved {cov_val:.1f}% code coverage ({files_str} files scanned). Uninspected files may contain additional cryptographic usages.")
        else:
            limitations.append(f"• <b>Full Coverage:</b> 100% of target files ({files_str}) were parsed by static analysis.")
    else:
        limitations.append("• <b>Coverage Notice:</b> Scan coverage metrics were not reported in scan metadata.")

    limitations.append(
        "• <b>Static Analysis Scope:</b> Findings represent declared cryptographic primitives identified in static source code "
        "and manifests. Dynamic TLS cipher suite negotiation, external microservice endpoints, and hardware security modules (HSMs) "
        "should be validated through runtime TLS socket inspection."
    )

    limitations_text = "<br/><br/>".join(limitations)
    t_limitations = Table([[Paragraph(limitations_text, ParagraphStyle('Lim', parent=body_style, fontSize=7.5, leading=10.5))]], colWidths=[532])
    t_limitations.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0, 0), (-1, -1), 6)
    ]))
    story.append(t_limitations)

    # Build PDF with dynamic page numbering
    canvasmaker: Any = ReportNumberedCanvas
    doc.build(story, canvasmaker=canvasmaker)
    return buffer.getvalue()
