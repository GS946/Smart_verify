# AICTE SmartVerify AI - System Architecture

## 1. Overview
**AICTE SmartVerify AI** is an AI-assisted decision-support platform designed to automate the preliminary verification and scrutiny of AICTE Extension of Approval (EoA) applications. Built for the **Smart India Hackathon 2026**, the system operates 100% offline, uses synthetic institutional data, and implements deterministic rule engines, computer vision forensics, cryptographic signature verification, and an immutable hash-chained audit ledger.

> [!IMPORTANT]
> **Strict Decision-Support Principle**: No automated component can approve or deny an institution. Final approval or denial remains strictly with authorized AICTE officers. Every UI screen displays the statutory warning banner:
> *"Decision-support system. Final approval/denial remains with competent AICTE authorities."*

---

## 2. Core Subsystems

### A. Secure Ingestion Pipeline (`app/services/ingestion.py`)
- **MIME & Size Enforcement**: Rejects non-PDF/image files or payloads exceeding 25 MB.
- **Malware Signature Screening**: Scans file headers for dangerous executable magic bytes (`MZ`, `ELF`, embedded scripts).
- **Cryptographic Hashing**: Computes SHA-256 upon arrival.
- **Write-Once Encrypted Storage**: Stores files using Fernet AES-128 encryption. Original files are immutable and cannot be overwritten.
- **Data Retention & Automated Purge**: Configurable retention window (default 180 days) with automated cleanup job.

### B. Document Intelligence (`app/services/extraction.py`)
- **PyMuPDF Text & Coordinate Extraction**: Parses PDF text streams into localized word blocks and bounding boxes `(x, y, w, h)`.
- **Classification**: Categorizes statutory filings into Affidavit, Undertaking, NOC-Fire, NOC-Affiliating University, Accreditation certificate, TER payment receipt, etc.
- **Regex & Normalization**: Standardizes dates to `YYYY-MM-DD` and extracts numeric intake capacities.

### C. Deterministic Rule Engine (`app/services/rules.py`)
- Evaluates versioned YAML rule packs per category (`EoA-Continuation`, `New-Programme`, `Intake-Change`).
- Every finding is evidence-linked:
  - Finding ID
  - Rule ID
  - Severity (`Critical`, `Major`, `Minor`)
  - Clause reference (e.g. `SYNTHETIC-DEMO-CH2-CL4.1`) and version
  - Extracted value vs AICTE baseline comparison value
  - Source document, page number, and bounding box
  - Plain-language reason: `"indicator requiring human verification"`

### D. Issuer Verification Adapters (`app/services/issuer_adapters.py`)
- **DigiLockerAdapter**: Queries simulated government repository.
- **QRSignedRecordAdapter**: Verifies Ed25519 digital signatures on synthetic documents using a deterministic public key.
- **AffiliatingUniversityAdapter**: Cross-checks university affiliation orders.
- Simulates deterministic outages and pending states for repeatable evaluations.

### E. Authenticity & Tampering Forensics (`app/services/forensics.py`)
- **SHA-256 Collision**: Identifies cross-institutional document reuse.
- **Perceptual Hashing (pHash)**: 64-bit image hashing to detect near-duplicate campus photographs across institutions or duplicate room submissions.
- **PDF Metadata Divergence**: Detects discrepancies between creation and modification timestamps or editing tools (Photoshop, Canva).
- **Error Level Analysis (ELA)**: Identifies JPEG compression inconsistencies indicating digital overlay tampering.

### F. Infrastructure Evidence Assist (`app/services/infra_evidence.py`)
- Blur detection via Laplacian variance ($< 50.0$ threshold).
- Brightness and resolution verification.
- Facility type classification (Computer Lab, Library, Workshop, Classroom).
- Provides triage recommendations only: *"sufficient clarity"* vs *"needs additional evidence / recommend physical inspection"*.

### G. Hybrid RAG Assistant (`app/services/rag.py`)
- Lexical and semantic retrieval over synthetic approval handbook clauses (`knowledge_base/synthetic_handbook_clauses.md`).
- Returns structured explanations with citations.
- Explicitly abstains with *"Not found in knowledge base"* when no clause exists; never invents rules.

### H. Transparent Risk Priority Scoring (`app/services/risk.py`)
- Transparent weighted formula:
  $$\text{Score} = \min(100, 35 \times \text{Critical} + 15 \times \text{Major} + 5 \times \text{Minor} + 10 \times \text{UnresolvedVerifications})$$
- Bands: High ($\ge 70$), Medium ($40-69$), Low ($10-39$), Minimal ($< 10$).
- Strictly maps into the 4 allowed outcome states:
  1. `Preliminary check complete`
  2. `Rectification required`
  3. `Manual review / inspection recommended`
  4. `Ready for official scrutiny`

### I. Cryptographic Hash-Chained Audit Ledger (`app/services/audit.py`)
- Every action, rule evaluation, login, and reviewer decision is recorded in an immutable append-only ledger.
- Block hash:
  $$\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{Timestamp} \parallel \text{Actor} \parallel \text{Role} \parallel \text{Action} \parallel \text{TargetID} \parallel \text{Details})$$
- Self-verifying chain integrity checker.
