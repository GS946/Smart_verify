from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.entities import Application, Finding, IssuerVerification

def compute_risk_score(critical_count: int, major_count: int, minor_count: int, unresolved_verifications: int) -> Dict[str, Any]:
    """
    Transparent regulatory formula:
    score = min(100, 35 * Critical + 15 * Major + 5 * Minor + 10 * unresolved_verifications)
    """
    raw_score = (35 * critical_count) + (15 * major_count) + (5 * minor_count) + (10 * unresolved_verifications)
    final_score = min(100.0, float(raw_score))

    if final_score >= 70.0:
        band = "High"
    elif final_score >= 40.0:
        band = "Medium"
    elif final_score >= 10.0:
        band = "Low"
    else:
        band = "Minimal"

    return {
        "score": final_score,
        "band": band,
        "formula": "min(100, 35×Critical + 15×Major + 5×Minor + 10×UnresolvedVerifications)",
        "breakdown": {
            "critical_findings": critical_count,
            "critical_weight": 35,
            "critical_subtotal": 35 * critical_count,
            "major_findings": major_count,
            "major_weight": 15,
            "major_subtotal": 15 * major_count,
            "minor_findings": minor_count,
            "minor_weight": 5,
            "minor_subtotal": 5 * minor_count,
            "unresolved_verifications": unresolved_verifications,
            "verification_weight": 10,
            "verification_subtotal": 10 * unresolved_verifications
        }
    }

class RiskScoringService:
    @staticmethod
    def determine_recommended_outcome(crit: int, maj: int, min_: int, has_unresolved_verification: bool, score: float = 0.0) -> str:
        # Strictly 4 allowed outcome states
        if crit > 0 or score >= 70.0:
            return "Manual review / inspection recommended"
        elif maj > 0:
            return "Rectification required"
        elif has_unresolved_verification:
            # Pending or failed issuer verification blocks "Ready for official scrutiny"
            return "Manual review / inspection recommended"
        elif min_ > 0:
            # Minor-only findings require rectification of minor deficiencies
            return "Rectification required"
        else:
            # Clean record with all verifications verified
            return "Ready for official scrutiny"

    @classmethod
    def calculate_and_update_application_risk(cls, db: Session, app_id: str) -> Dict[str, Any]:
        app = db.query(Application).filter(Application.id == app_id).first()
        if not app:
            return {"score": 0.0, "band": "Minimal"}

        findings = db.query(Finding).filter(Finding.application_id == app_id).all()
        verifications = db.query(IssuerVerification).filter(IssuerVerification.application_id == app_id).all()

        crit = sum(1 for f in findings if f.severity == "Critical")
        maj = sum(1 for f in findings if f.severity == "Major")
        minr = sum(1 for f in findings if f.severity == "Minor")

        unresolved_verif = sum(
            1 for v in verifications
            if v.status in {"MISMATCH_DETECTED", "SOURCE_UNAVAILABLE", "MANUAL_REVIEW_REQUIRED"}
        )

        res = compute_risk_score(crit, maj, minr, unresolved_verif)

        app.risk_score = res["score"]
        app.risk_band = res["band"]

        # Determine System-Computed Recommended State (Strictly 4 allowed states)
        recommended = cls.determine_recommended_outcome(
            crit=crit,
            maj=maj,
            min_=minr,
            has_unresolved_verification=(unresolved_verif > 0),
            score=res["score"]
        )

        app.recommended_status = recommended

        # Re-evaluation must NEVER overwrite a human officer's workflow decision
        if not app.workflow_status:
            app.status = recommended
        else:
            app.status = app.workflow_status

        db.commit()
        return res
