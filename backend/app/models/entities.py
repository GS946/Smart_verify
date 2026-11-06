from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.models.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(String(50), primary_key=True)
    username = Column(String(50), unique=True, index=True)
    password_hash = Column(String(128))
    full_name = Column(String(100))
    role = Column(String(50))  # Applicant, Scrutiny Officer, Admin, Auditor
    institution_id = Column(String(50), nullable=True)

class Institution(Base):
    __tablename__ = "institutions"
    id = Column(String(50), primary_key=True)
    name = Column(String(200), index=True)
    location = Column(String(200))
    region = Column(String(50))
    category = Column(String(50))

class Application(Base):
    __tablename__ = "applications"
    id = Column(String(50), primary_key=True) # e.g. APP-2026-SIT01
    institution_id = Column(String(50), ForeignKey("institutions.id"), index=True)
    institution_name = Column(String(200))
    category = Column(String(50)) # EoA-Continuation, New-Programme, Intake-Change
    academic_year = Column(String(20), default="2026-27")
    declared_intake = Column(Integer, default=60)
    
    # 4 Allowed Outcome States Only:
    # 1. "Preliminary check complete"
    # 2. "Rectification required"
    # 3. "Manual review / inspection recommended"
    # 4. "Ready for official scrutiny"
    status = Column(String(60), default="Preliminary check complete")
    recommended_status = Column(String(60), default="Preliminary check complete")
    workflow_status = Column(String(60), nullable=True) # Set only by human officer action
    
    risk_score = Column(Float, default=0.0)
    risk_band = Column(String(20), default="Minimal") # Minimal, Low, Medium, High
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    documents = relationship("Document", back_populates="application")
    findings = relationship("Finding", back_populates="application")

class BaselineRecord(Base):
    __tablename__ = "baseline_records"
    institution_id = Column(String(50), primary_key=True)
    approved_intake = Column(Integer, default=60)
    approved_programmes = Column(JSON, default=list)
    ter_payment_status = Column(String(30), default="PAID") # PAID, PENDING, UNPAID
    accreditation_status = Column(String(30), default="VALID") # VALID, EXPIRED, NONE
    previous_eoa_status = Column(String(30), default="APPROVED")
    deficiency_count = Column(Integer, default=0)

class Document(Base):
    __tablename__ = "documents"
    id = Column(String(50), primary_key=True)
    application_id = Column(String(50), ForeignKey("applications.id"), index=True)
    doc_type = Column(String(100), index=True)
    filename = Column(String(255))
    storage_path = Column(String(500))
    sha256_hash = Column(String(64), index=True)
    page_count = Column(Integer, default=1)
    encrypted = Column(Boolean, default=True)
    is_corrupted = Column(Boolean, default=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    application = relationship("Application", back_populates="documents")
    fields = relationship("ExtractionField", back_populates="document")

class ExtractionField(Base):
    __tablename__ = "extraction_fields"
    id = Column(String(60), primary_key=True)
    document_id = Column(String(50), ForeignKey("documents.id"), index=True)
    application_id = Column(String(50), index=True)
    field_name = Column(String(100), index=True)
    raw_value = Column(Text)
    normalized_value = Column(Text)
    page_num = Column(Integer, default=1)
    bbox_x = Column(Float, default=0.0)
    bbox_y = Column(Float, default=0.0)
    bbox_w = Column(Float, default=0.0)
    bbox_h = Column(Float, default=0.0)
    confidence = Column(Float, default=0.95)

    document = relationship("Document", back_populates="fields")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(String(60), primary_key=True)
    application_id = Column(String(50), ForeignKey("applications.id"), index=True)
    document_id = Column(String(50), nullable=True)
    rule_id = Column(String(50), index=True)
    clause_ref = Column(String(100)) # e.g. SYNTHETIC-DEMO-CH3-CL5.2
    clause_version = Column(String(20), default="1.0.0")
    severity = Column(String(20)) # Critical, Major, Minor
    extracted_value = Column(Text, nullable=True)
    comparison_value = Column(Text, nullable=True)
    source_document = Column(String(100), nullable=True)
    page_number = Column(Integer, default=1)
    bbox = Column(JSON, nullable=True) # {x, y, w, h}
    confidence = Column(Float, default=0.95)
    plain_reason = Column(Text) # "indicator requiring human verification"
    review_status = Column(String(30), default="Pending") # Confirmed, False positive, Pending
    reviewer_comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    application = relationship("Application", back_populates="findings")

class IssuerVerification(Base):
    __tablename__ = "issuer_verifications"
    id = Column(String(60), primary_key=True)
    application_id = Column(String(50), index=True)
    document_id = Column(String(50), nullable=True)
    adapter_name = Column(String(50)) # DigiLockerAdapter, QRSignedAdapter, UniversityAdapter
    reference_no = Column(String(100))
    status = Column(String(50)) # VERIFIED, MISMATCH_DETECTED, EXPIRED, PENDING, SOURCE_UNAVAILABLE, NOT_SUPPORTED, MANUAL_REVIEW_REQUIRED
    response_data = Column(JSON, default=dict)
    verified_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(60), primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    actor_id = Column(String(50))
    actor_role = Column(String(50))
    action = Column(String(100)) # login, rule_applied, record_checked, issuer_response, alert_fired, ai_output, reviewer_action
    target_type = Column(String(50)) # application, document, rule, auth
    target_id = Column(String(100))
    details = Column(JSON, default=dict)
    prev_hash = Column(String(64))
    current_hash = Column(String(64), index=True)

class AnomalyThreshold(Base):
    __tablename__ = "anomaly_thresholds"
    id = Column(String(50), primary_key=True)
    detector_name = Column(String(100), unique=True)
    threshold_value = Column(Float)
    description = Column(String(255))
    updated_at = Column(DateTime, default=datetime.utcnow)
    updated_by = Column(String(50), default="system_admin")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String(60), primary_key=True)
    application_id = Column(String(50), index=True)
    institution_name = Column(String(200))
    severity = Column(String(20)) # Critical, Major, Minor, Info
    alert_type = Column(String(50)) # missing_doc, expiry_soon, verification_pending, anomaly_flag, infra_gap, high_risk
    message = Column(Text)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class RulePack(Base):
    __tablename__ = "rule_packs"
    id = Column(String(50), primary_key=True) # e.g. EoA-Continuation-v1
    category = Column(String(50), index=True)
    academic_year = Column(String(20))
    version = Column(String(20))
    is_active = Column(Boolean, default=True)
    rules_json = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    updated_by = Column(String(50), default="admin")
