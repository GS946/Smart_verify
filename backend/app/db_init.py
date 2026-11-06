import os
import sys
import json
from datetime import datetime
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.models.database import engine, Base, SessionLocal
from app.models.entities import (
    User, Institution, Application, BaselineRecord,
    Document, ExtractionField, Finding, AnomalyThreshold, Alert, RulePack, IssuerVerification
)
from app.core.security import hash_password
from app.services.ingestion import SecureIngestionService
from app.services.extraction import DocumentIntelligenceService
from app.services.rules import DeterministicRuleEngine
from app.services.risk import RiskScoringService
from app.services.audit import AuditService
from app.services.issuer_adapters import IssuerVerificationManager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SEED_PATH = os.path.join(BASE_DIR, "..", "..", "data", "seed_output", "seed_database.json")
RULES_DIR = os.path.join(BASE_DIR, "..", "..", "rules")

def init_db():
    print("[DB Init] Creating database tables...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Check if already seeded
    user_count = db.query(User).count()
    if user_count > 0:
        print("[DB Init] Database already initialized with users.")
        db.close()
        return

    print("[DB Init] Seeding demo users with RBAC...")
    demo_users = [
        User(
            id="USR-OFFICER-01",
            username="officer_sharma",
            password_hash=hash_password("officer123"),
            full_name="Dr. R. K. Sharma (Senior Scrutiny Officer)",
            role="Scrutiny Officer"
        ),
        User(
            id="USR-APPLICANT-01",
            username="applicant_sit",
            password_hash=hash_password("applicant123"),
            full_name="Dr. A. K. Verma (Registrar, Sunrise Institute of Technology)",
            role="Applicant",
            institution_id="AICTE-SIT-001"
        ),
        User(
            id="USR-ADMIN-01",
            username="admin_aicte",
            password_hash=hash_password("admin123"),
            full_name="Director (Approval Bureau - AICTE)",
            role="Admin"
        ),
        User(
            id="USR-AUDITOR-01",
            username="auditor_cag",
            password_hash=hash_password("auditor123"),
            full_name="Compliance Officer (Statutory Vigilance & Audit)",
            role="Auditor"
        ),
    ]
    db.add_all(demo_users)
    db.commit()

    # Default Anomaly Thresholds
    thresholds = [
        AnomalyThreshold(
            id="TH-PHASH-01",
            detector_name="phash_similarity_threshold",
            threshold_value=90.0,
            description="Perceptual hash similarity threshold percentage for flagging image/document reuse"
        ),
        AnomalyThreshold(
            id="TH-LAPLACIAN-02",
            detector_name="blur_laplacian_threshold",
            threshold_value=50.0,
            description="Minimum Laplacian variance for acceptable photographic evidence clarity"
        ),
        AnomalyThreshold(
            id="TH-ELA-03",
            detector_name="ela_difference_threshold",
            threshold_value=35.0,
            description="Error Level Analysis mean difference threshold for identifying visual overlay edits"
        ),
    ]
    db.add_all(thresholds)
    db.commit()

    # Seed Rule Packs
    for cat in ["EoA-Continuation", "New-Programme", "Intake-Change"]:
        rf = os.path.join(RULES_DIR, f"{cat}.yaml")
        if os.path.exists(rf):
            import yaml
            with open(rf, "r") as f:
                rdata = yaml.safe_load(f)
                rp = RulePack(
                    id=f"PACK-{cat}-2026",
                    category=cat,
                    academic_year=rdata.get("academic_year", "2026-27"),
                    version=rdata.get("version", "1.0.0"),
                    is_active=True,
                    rules_json=rdata.get("rules", [])
                )
                db.add(rp)
    db.commit()

    # Seed from seed_database.json if exists
    if os.path.exists(SEED_PATH):
        print(f"[DB Init] Loading synthetic dataset from {SEED_PATH}...")
        with open(SEED_PATH, "r") as f:
            seed_data = json.load(f)

        # 1. Institutions
        for item in seed_data.get("institutions", []):
            inst = Institution(
                id=item["institution_id"],
                name=item["name"],
                location=item["location"],
                region=item["region"],
                category=item["category"]
            )
            db.add(inst)
        db.commit()

        # 2. Baseline Records
        for b_item in seed_data.get("baseline_records", []):
            rec = BaselineRecord(
                institution_id=b_item["institution_id"],
                approved_intake=b_item["approved_intake"],
                approved_programmes=b_item["approved_programmes"],
                ter_payment_status=b_item["ter_payment_status"],
                accreditation_status=b_item["accreditation_status"],
                previous_eoa_status=b_item["previous_eoa_status"],
                deficiency_count=b_item["deficiency_count"]
            )
            db.add(rec)
        db.commit()

        # 3. Applications and Documents
        for app_item in seed_data.get("applications", []):
            app = Application(
                id=app_item["application_id"],
                institution_id=app_item["institution_id"],
                institution_name=app_item["institution_name"],
                category=app_item["category"],
                academic_year=app_item["academic_year"],
                declared_intake=app_item["declared_intake"],
                status=app_item["status"],
                recommended_status=app_item["status"],
                workflow_status=None,
                risk_score=0.0,
                risk_band="Minimal"
            )
            db.add(app)
            db.commit()

            # Add documents & extract fields
            for d_info in app_item.get("documents", []):
                doc_path = d_info.get("filepath")
                if doc_path and os.path.exists(doc_path):
                    with open(doc_path, "rb") as f_in:
                        doc_bytes = f_in.read()

                    ingest_res = SecureIngestionService.ingest_document(
                        raw_bytes=doc_bytes,
                        filename=d_info["filename"],
                        application_id=app.id,
                        uploader_id="SYSTEM_SEED",
                        doc_type=d_info["doc_type"]
                    )

                    doc_entry = Document(
                        id=d_info["doc_id"],
                        application_id=app.id,
                        doc_type=d_info["doc_type"],
                        filename=d_info["filename"],
                        storage_path=ingest_res["storage_path"],
                        sha256_hash=d_info["sha256"],
                        page_count=d_info.get("page_count", 1),
                        encrypted=True,
                        is_corrupted=False
                    )
                    db.add(doc_entry)
                    db.commit()

                    # Extract document fields with PyMuPDF
                    ext = DocumentIntelligenceService.extract_from_pdf_stream(doc_bytes, d_info["filename"])
                    if ext.get("validity_date"):
                        f_entry = ExtractionField(
                            id=f"FLD-{doc_entry.id}-VAL",
                            document_id=doc_entry.id,
                            application_id=app.id,
                            field_name="validity_date",
                            raw_value=str(ext["validity_date"]),
                            normalized_value=str(ext["validity_date"]),
                            page_num=1,
                            bbox_x=50.0,
                            bbox_y=195.0,
                            bbox_w=150.0,
                            bbox_h=15.0,
                            confidence=0.98
                        )
                        db.add(f_entry)

                    if ext.get("declared_intake"):
                        f_entry = ExtractionField(
                            id=f"FLD-{doc_entry.id}-INTK",
                            document_id=doc_entry.id,
                            application_id=app.id,
                            field_name="declared_intake",
                            raw_value=str(ext["declared_intake"]),
                            normalized_value=str(ext["declared_intake"]),
                            page_num=1,
                            confidence=0.98
                        )
                        db.add(f_entry)

            db.commit()

            # Run issuer verifications
            app_docs = db.query(Document).filter(Document.application_id == app.id).all()
            for doc in app_docs:
                cert_no = f"CERT-{app.institution_id}-{doc.doc_type[:4]}"
                qr_val = f"DOC:{doc.doc_type}|ID:{app.institution_id}|VALID:2026"
                if app.id == "APP-2026-SIT01" and doc.doc_type == "NOC-Affiliating University":
                    qr_val = f"DOC:AFFIL|ID:AICTE-SIT-001|VALID:2024-06-30|SIG:ed25519_tampered_demo_token"
                payload = {"qr_payload": qr_val}
                res = IssuerVerificationManager.run_all_verifications(doc.doc_type, cert_no, app.institution_id, payload)
                primary = res["primary"]
                v_entry = IssuerVerification(
                    id=f"IV-{doc.id}-{primary['adapter'][:4]}",
                    application_id=app.id,
                    document_id=doc.id,
                    adapter_name=primary["adapter"],
                    reference_no=cert_no,
                    status=primary["status"],
                    response_data=primary,
                    verified_at=datetime.utcnow()
                )
                db.add(v_entry)
            db.commit()

            # Run deterministic rule engine
            DeterministicRuleEngine.evaluate_application(db, app.id)
            # Update risk score and outcome state
            RiskScoringService.calculate_and_update_application_risk(db, app.id)

        # Audit initial seed
        AuditService.record_event(
            db=db,
            actor_id="SYSTEM",
            actor_role="Admin",
            action="database_seed_completed",
            target_type="system",
            target_id="DATABASE",
            details={"institutions_seeded": len(seed_data.get("institutions", []))}
        )

        print("[DB Init] All 40 applications evaluated, scored, and seeded with audit ledger!")

    db.close()

if __name__ == "__main__":
    init_db()
