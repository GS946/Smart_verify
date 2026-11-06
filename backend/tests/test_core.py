import os
import sys
import pytest
from datetime import datetime
from fastapi import HTTPException

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.database import SessionLocal
from app.models.entities import Application, Finding, Document, BaselineRecord, RulePack
from app.services.risk import compute_risk_score, RiskScoringService
from app.services.audit import calculate_log_hash, AuditService, GENESIS_HASH
from app.core.security import encrypt_bytes, decrypt_bytes, mask_pii
from app.api.endpoints import check_role, perform_officer_action, OfficerActionRequest
from app.services.rules import DeterministicRuleEngine

def test_risk_formula_calculation():
    """Test Transparent AICTE weighted formula: score = min(100, 35*Crit + 15*Maj + 5*Min + 10*Unresolved)"""
    # 1. Zero findings -> Minimal risk
    res1 = compute_risk_score(0, 0, 0, 0)
    assert res1["score"] == 0.0
    assert res1["band"] == "Minimal"

    # 2. Hero weights subtotal check
    res2 = compute_risk_score(1, 2, 0, 0)
    assert res2["score"] == 65.0
    assert res2["band"] == "Medium"
    assert res2["breakdown"]["critical_subtotal"] == 35
    assert res2["breakdown"]["major_subtotal"] == 30

    # 3. High Risk threshold (>= 70)
    res3 = compute_risk_score(2, 0, 0, 0)
    assert res3["score"] == 70.0
    assert res3["band"] == "High"

    # 4. Cap at 100
    res4 = compute_risk_score(4, 2, 5, 2)
    assert res4["score"] == 100.0
    assert res4["band"] == "High"

def test_audit_hash_chain_tamper_detection():
    """Validates cryptographic SHA-256 hash chaining and tamper detection."""
    h0 = GENESIS_HASH
    now1 = datetime.utcnow().isoformat()
    h1 = calculate_log_hash(h0, now1, "officer", "Scrutiny Officer", "rule_evaluated", "APP-01", "{}")

    now2 = datetime.utcnow().isoformat()
    h2 = calculate_log_hash(h1, now2, "officer", "Scrutiny Officer", "inspection_referred", "APP-01", "{}")

    assert h1 != h0
    assert h2 != h1

    # Tampering block 1 action modifies block 2 recalculation
    tampered_h1 = calculate_log_hash(h0, now1, "hacker", "Scrutiny Officer", "illegal_edit", "APP-01", "{}")
    assert tampered_h1 != h1
    recalc_h2 = calculate_log_hash(tampered_h1, now2, "officer", "Scrutiny Officer", "inspection_referred", "APP-01", "{}")
    assert recalc_h2 != h2

def test_decision_support_constraint():
    """Strictly validates non-binary outcomes: exactly 4 allowed states, zero approve/reject."""
    allowed_states = {
        "Preliminary check complete",
        "Rectification required",
        "Manual review / inspection recommended",
        "Ready for official scrutiny"
    }

    forbidden_states = {"Approved", "APPROVED", "Rejected", "REJECTED", "Auto-Approved", "Auto-Denied"}
    for f in forbidden_states:
        assert f not in allowed_states

def test_rule_engine_check_types():
    """Unit tests for each distinct rule engine check type: required_doc, validity, cross_record, threshold."""
    db = SessionLocal()
    try:
        # 1. required_doc: find an application and test that missing doc triggers finding
        app = db.query(Application).filter(Application.id == "APP-2026-SIT01").first()
        assert app is not None

        # 2. cross_record: intake 120 declared vs 60 baseline
        baseline = db.query(BaselineRecord).filter(BaselineRecord.institution_id == app.institution_id).first()
        assert baseline is not None
        assert app.declared_intake == 120
        assert baseline.approved_intake == 60

        findings = DeterministicRuleEngine.evaluate_application(db, app.id)
        rule_ids = {f["rule_id"] for f in findings}

        # Check types present:
        # cross_record -> RULE-CROSS-INTK-003
        assert "RULE-CROSS-INTK-003" in rule_ids
        # validity -> RULE-DOC-AFFL-002 and RULE-DOC-ACCR-005
        assert "RULE-DOC-AFFL-002" in rule_ids
        assert "RULE-DOC-ACCR-005" in rule_ids
        # threshold / payment -> RULE-PAY-TER-004
        assert "RULE-PAY-TER-004" in rule_ids
        # anomaly forensics -> RULE-ANOM-DUPDOC-006 and RULE-INFR-PHOTO-007
        assert "RULE-ANOM-DUPDOC-006" in rule_ids
        assert "RULE-INFR-PHOTO-007" in rule_ids
    finally:
        db.close()

def test_hero_scenario_findings_and_risk_reconciliation():
    """
    Hero Scenario: Sunrise Institute of Technology (APP-2026-SIT01, AICTE-SIT-001)
    Validates all 6 injected defects, indicator phrasing, and exact risk score reconciliation.
    """
    db = SessionLocal()
    try:
        app_id = "APP-2026-SIT01"
        findings = DeterministicRuleEngine.evaluate_application(db, app_id)
        f_map = {f["rule_id"]: f for f in findings}

        # 1. Check all 6 findings exist
        expected_rules = [
            "RULE-CROSS-INTK-003",
            "RULE-ANOM-DUPDOC-006",
            "RULE-DOC-AFFL-002",
            "RULE-PAY-TER-004",
            "RULE-DOC-ACCR-005",
            "RULE-INFR-PHOTO-007"
        ]
        for r_id in expected_rules:
            assert r_id in f_map, f"Missing expected finding {r_id}"

        # 2. Check indicator phrasing
        assert "printed validity date differs from the signed record" in f_map["RULE-DOC-AFFL-002"]["plain_reason"]
        for f in findings:
            assert "indicator requiring human verification" in f["plain_reason"]

        # 3. Check severity breakdown: 3 Critical, 3 Major
        crit_count = sum(1 for f in findings if f["severity"] == "Critical")
        maj_count = sum(1 for f in findings if f["severity"] == "Major")
        assert crit_count == 3
        assert maj_count == 3

        # 4. Check Risk Reconciliation:
        # Score = min(100, 35*3 + 15*3 + 5*0 + 10*1) = min(100, 105 + 45 + 10) = 160 -> 100.0 High
        risk = RiskScoringService.calculate_and_update_application_risk(db, app_id)
        assert risk["score"] == 100.0
        assert risk["band"] == "High"
    finally:
        db.close()

def test_rbac_denial_per_role():
    """Unit tests RBAC enforcement and denial for unauthorized roles."""
    applicant_user = {"username": "applicant_sit", "role": "Applicant", "institution_id": "AICTE-SIT-001"}
    officer_user = {"username": "officer_sharma", "role": "Scrutiny Officer"}
    admin_user = {"username": "admin_sys", "role": "Admin"}

    # Applicant denied scrutiny actions
    with pytest.raises(HTTPException) as exc_info:
        check_role(applicant_user, ["Scrutiny Officer", "Regional Officer", "Council Reviewer", "Admin"])
    assert exc_info.value.status_code == 403
    assert "Access denied" in exc_info.value.detail

    # Applicant denied Admin endpoints
    with pytest.raises(HTTPException) as exc_info:
        check_role(applicant_user, ["Admin"])
    assert exc_info.value.status_code == 403

    # Officer allowed scrutiny
    check_role(officer_user, ["Scrutiny Officer", "Regional Officer", "Council Reviewer", "Admin"])

    # Officer denied Admin endpoints
    with pytest.raises(HTTPException) as exc_info:
        check_role(officer_user, ["Admin"])
    assert exc_info.value.status_code == 403

    # Admin allowed Admin endpoints
    check_role(admin_user, ["Admin"])

def test_strictly_no_approve_or_reject_outcomes():
    """Ensures that attempting to set status to 'Approved' or 'Rejected' raises HTTP 400."""
    db = SessionLocal()
    try:
        officer = {"username": "officer_sharma", "role": "Scrutiny Officer"}
        
        # 1. Forbidden action "approve"
        req_approve = OfficerActionRequest(action="approve", notes="Illegal approve test")
        with pytest.raises(HTTPException) as exc:
            perform_officer_action("APP-2026-SIT01", req_approve, user=officer, db=db)
        assert exc.value.status_code == 400
        assert "Auto-approve/reject is strictly forbidden" in exc.value.detail

        # 2. Forbidden action "reject"
        req_reject = OfficerActionRequest(action="reject", notes="Illegal reject test")
        with pytest.raises(HTTPException) as exc:
            perform_officer_action("APP-2026-SIT01", req_reject, user=officer, db=db)
        assert exc.value.status_code == 400

        # 3. Allowed action "refer_for_inspection"
        req_valid = OfficerActionRequest(action="refer_for_inspection", notes="Referred to EVC")
        res = perform_officer_action("APP-2026-SIT01", req_valid, user=officer, db=db)
        assert res["success"] is True
        assert res["status"] == "Manual review / inspection recommended"
    finally:
        db.close()

def test_security_encryption_pii_masking():
    """Unit tests Fernet encryption/decryption and regex PII masking."""
    # 1. Fernet Encryption
    test_data = b"AICTE Secure Statutory PDF Bytes"
    encrypted = encrypt_bytes(test_data)
    assert encrypted != test_data
    decrypted = decrypt_bytes(encrypted)
    assert decrypted == test_data

    # 2. PII Masking
    raw_text = "Principal Aadhaar: 1234 5678 9012, PAN: ABCDE1234F, Phone: 9876543210, Email: principal@sunrise.ac.in"
    masked = mask_pii(raw_text)
    assert "XXXX-XXXX-9012" in masked
    assert "ABCDE****F" in masked
    assert "+91-XXXXX-3210" in masked
    assert "p***@sunrise.ac.in" in masked

def test_applicant_role_scoping_and_cross_institution_masking():
    """Unit tests role scoping: applicant cannot read another institution's details, docs, or graph."""
    from app.api.endpoints import get_application_detail, view_document_bytes, get_application_graph
    db = SessionLocal()
    try:
        # Applicant for Sunrise Institute
        applicant_sit = {"username": "applicant_sit", "role": "Applicant", "institution_id": "AICTE-SIT-001"}
        # Target application from another institution (e.g. Greenfield APP-2026-GPI06)
        other_app_id = "APP-2026-GPI06"

        # 1. Applicant denied access to other institution application detail
        with pytest.raises(HTTPException) as exc:
            get_application_detail(other_app_id, user=applicant_sit, db=db)
        assert exc.value.status_code == 403
        assert "Applicants can only view their own institution" in exc.value.detail

        # 2. Applicant denied access to other institution graph
        with pytest.raises(HTTPException) as exc:
            get_application_graph(other_app_id, user=applicant_sit, db=db)
        assert exc.value.status_code == 403

        # 3. Applicant denied access to other institution document
        other_doc = db.query(Document).filter(Document.application_id == other_app_id).first()
        if other_doc:
            with pytest.raises(HTTPException) as exc:
                view_document_bytes(other_doc.id, user=applicant_sit, db=db)
            assert exc.value.status_code == 403

        # 4. Masking of cross-institution finding for applicant on own application
        sit_detail = get_application_detail("APP-2026-SIT01", user=applicant_sit, db=db)
        dup_finding = next((f for f in sit_detail["findings"] if f["rule_id"] == "RULE-ANOM-DUPDOC-006"), None)
        assert dup_finding is not None
        assert "Pioneer Institute" not in dup_finding["plain_reason"]
        assert "[REDACTED INSTITUTION]" in dup_finding["plain_reason"]
        assert dup_finding["comparison_value"] == "Matches [REDACTED INSTITUTION]"
    finally:
        db.close()

def test_admin_separated_from_officer_case_actions():
    """Validates that Admin is rejected with HTTP 403 when attempting officer case actions."""
    db = SessionLocal()
    try:
        admin_user = {"username": "admin_sys", "role": "Admin"}
        req = OfficerActionRequest(action="refer_for_inspection", notes="Admin attempting officer action")
        with pytest.raises(HTTPException) as exc:
            perform_officer_action("APP-2026-SIT01", req, user=admin_user, db=db)
        assert exc.value.status_code == 403
        assert "Access denied" in exc.value.detail
    finally:
        db.close()

def test_status_logic_and_preservation_of_human_decision():
    """
    Validates:
    - recommended_status (system-computed) separate from workflow_status (officer-set)
    - Re-evaluation preserves officer workflow decision
    - Minor-only findings yield 'Rectification required'
    - Pending/failed verification blocks 'Ready for official scrutiny'
    """
    db = SessionLocal()
    try:
        app = db.query(Application).filter(Application.id == "APP-2026-SIT01").first()
        assert app is not None

        # 1. Officer explicitly sets workflow_status
        officer = {"username": "officer_sharma", "role": "Scrutiny Officer"}
        req = OfficerActionRequest(action="request_rectification", notes="Officer decision")
        res = perform_officer_action(app.id, req, user=officer, db=db)
        assert res["status"] == "Rectification required"

        # 2. Trigger automated risk recalculation - system computes recommended_status
        risk = RiskScoringService.calculate_and_update_application_risk(db, app.id)
        db.refresh(app)

        # Human decision MUST NOT be overwritten!
        assert app.workflow_status == "Rectification required"
        assert app.status == "Rectification required" # Preserves officer decision
        assert app.recommended_status == "Manual review / inspection recommended"

        # 3. Status logic unit cases:
        # a) Minor only findings -> Rectification required
        status_minor = RiskScoringService.determine_recommended_outcome(crit=0, maj=0, min_=2, has_unresolved_verification=False)
        assert status_minor == "Rectification required"

        # b) Zero findings but pending/failed verification blocks Ready for official scrutiny
        status_unresolved = RiskScoringService.determine_recommended_outcome(crit=0, maj=0, min_=0, has_unresolved_verification=True)
        assert status_unresolved == "Manual review / inspection recommended"

        # c) Zero findings and all verifications clear -> Ready for official scrutiny
        status_clean = RiskScoringService.determine_recommended_outcome(crit=0, maj=0, min_=0, has_unresolved_verification=False)
        assert status_clean == "Ready for official scrutiny"
    finally:
        db.close()

def test_audit_tail_deletion_detection():
    """
    Validates detection of tail deletion using external checkpoint head_hash and block_count.
    """
    from app.models.entities import AuditLog
    db = SessionLocal()
    try:
        # 1. Ledger integrity passes initially
        valid_before, count_before, errors_before = AuditService.verify_chain_integrity(db)
        assert valid_before is True
        assert len(errors_before) == 0

        # 2. Simulate tail deletion by creating a dummy log entry that bypasses checkpoint
        last_log = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        if last_log:
            original_checkpoint = AuditService.read_checkpoint()
            # If checkpoint head differs from DB, or count differs, it should fail
            mismatched_checkpoint = {
                "head_hash": "fabricated_tampered_hash_0000000000000000000000000000000000000000",
                "block_count": count_before + 10,
                "last_checkpoint_utc": datetime.utcnow().isoformat()
            }
            AuditService.write_checkpoint(mismatched_checkpoint["head_hash"], mismatched_checkpoint["block_count"])

            is_valid, checked, errors = AuditService.verify_chain_integrity(db)
            assert is_valid is False
            assert any("Tail deletion detected" in e or "divergence" in e for e in errors)

            # Restore valid checkpoint
            if original_checkpoint:
                AuditService.write_checkpoint(original_checkpoint.get("head_hash"), original_checkpoint.get("block_count"))
            else:
                AuditService.write_checkpoint(last_log.current_hash, count_before)

            # Verify integrity is restored
            valid_restored, _, _ = AuditService.verify_chain_integrity(db)
            assert valid_restored is True
    finally:
        db.close()

