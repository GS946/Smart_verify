from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from app.models.entities import BaselineRecord, Institution, Application

class MockAICTERecordsService:
    """
    Simulated authorized AICTE central database service.
    Access restricted to authenticated Scrutiny Officers and System engines.
    """

    @staticmethod
    def get_institutional_baseline(db: Session, institution_id: str, actor_role: str = "Scrutiny Officer") -> Optional[Dict[str, Any]]:
        # Enforce role-based access
        if actor_role not in {"Scrutiny Officer", "Admin", "Auditor", "system"}:
            raise PermissionError("Access denied to central AICTE records: Insufficient privileges")

        record = db.query(BaselineRecord).filter(BaselineRecord.institution_id == institution_id).first()
        if not record:
            return None

        inst = db.query(Institution).filter(Institution.id == institution_id).first()

        return {
            "institution_id": record.institution_id,
            "institution_name": inst.name if inst else "Unknown Institution",
            "approved_intake": record.approved_intake,
            "approved_programmes": record.approved_programmes or ["Computer Science and Engineering"],
            "ter_payment_status": record.ter_payment_status,
            "accreditation_status": record.accreditation_status,
            "previous_eoa_status": record.previous_eoa_status,
            "deficiency_count": record.deficiency_count,
            "compliance_rating": "SATISFACTORY" if record.deficiency_count == 0 else "DEFICIENT",
            "verified_by_authority": "AICTE Approval Bureau (Simulated Record)"
        }

    @staticmethod
    def verify_ter_payment(db: Session, institution_id: str) -> Dict[str, Any]:
        record = db.query(BaselineRecord).filter(BaselineRecord.institution_id == institution_id).first()
        if not record:
            return {"status": "NOT_FOUND", "is_paid": False}
        return {
            "status": record.ter_payment_status,
            "is_paid": record.ter_payment_status == "PAID",
            "institution_id": institution_id
        }

    @staticmethod
    def verify_intake_ceiling(db: Session, institution_id: str, declared_intake: int) -> Dict[str, Any]:
        record = db.query(BaselineRecord).filter(BaselineRecord.institution_id == institution_id).first()
        if not record:
            return {"match": False, "approved_intake": 0, "difference": declared_intake}
        
        diff = declared_intake - record.approved_intake
        return {
            "approved_intake": record.approved_intake,
            "declared_intake": declared_intake,
            "difference": diff,
            "matches": (diff == 0),
            "exceeds": (diff > 0)
        }
