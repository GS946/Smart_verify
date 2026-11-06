# DPDP Act (2023) Compliance & Privacy Safeguards

## 1. Compliance Architecture Overview
AICTE SmartVerify AI is designed with Privacy-by-Design principles aligned with the **Digital Personal Data Protection Act (DPDP Act 2023)** of India. Even within this hackathon demonstration utilizing synthetic datasets, all personal and institutional identifiers adhere to strict privacy controls.

---

## 2. Key Privacy Safeguards

### A. Data Protection & Encryption at Rest
- All uploaded statutory filings, affidavits, certificates, and infrastructure photographs are encrypted immediately upon ingestion using **Fernet (AES-128-CBC with HMAC authentication)**.
- Raw files are never stored unencrypted on disk.
- Storage paths are generated from SHA-256 hashes, preventing direct enumeration or directory traversal.

### B. PII Masking in System Logs (`app/core/security.py`)
To prevent data leakage in application, server, or debug logs, the system enforces automated regex masking for sensitive identifiers:
- **Aadhaar Numbers**: Masked as `XXXX-XXXX-1234`
- **Income Tax PAN**: Masked as `ABCDE****F`
- **Mobile Numbers**: Masked as `+91-XXXXX-12345`
- **Email Addresses**: Masked as `u***@domain.com`

### C. Role-Based Access Control (RBAC)
Data access is restricted strictly by user roles:
- **Applicant**: Can only view and rectify documents belonging to their own designated institution.
- **Scrutiny Officer**: Authorized to view institutional filings, execute checklist rules, and record scrutiny observations.
- **Admin**: Authorized to configure checklist rules and adjust anomaly thresholds.
- **Auditor**: Read-only access to the cryptographic audit trail for vigilance and compliance verification.

### D. Data Retention & Automated Purge Job
- In accordance with the storage limitation mandate of Section 8(7) of the DPDP Act, uploaded documents are subject to a configurable retention policy (`DATA_RETENTION_DAYS`, default 180 days).
- The automated purge routine (`SecureIngestionService.purge_expired_records`) securely removes expired encrypted files once their statutory processing window has elapsed.

### E. Tamper-Evident Audit Accountability
Every system interaction—including login events, record lookups, rule evaluations, and officer comments—is appended to a cryptographically chained audit ledger. The hash chain guarantees non-repudiation and transparency for statutory vigilance.
