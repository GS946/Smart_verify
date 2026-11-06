import os
import json
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.entities import Alert, Application, Finding, Document, IssuerVerification

SIMULATED_EMAIL_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "storage", "simulated_emails.json")

class AlertService:
    @staticmethod
    def generate_alerts_for_application(db: Session, app_id: str) -> List[Dict[str, Any]]:
        """
        Scans application, findings, and verifications to fire proactive alerts.
        """
        app = db.query(Application).filter(Application.id == app_id).first()
        if not app:
            return []

        findings = db.query(Finding).filter(Finding.application_id == app_id).all()
        verifications = db.query(IssuerVerification).filter(IssuerVerification.application_id == app_id).all()

        alerts_to_create = []

        # 1. High Risk Alert
        if app.risk_score >= 70.0:
            alerts_to_create.append({
                "id": f"ALT-RISK-{app_id}",
                "app_id": app_id,
                "inst_name": app.institution_name,
                "severity": "Critical",
                "type": "high_risk",
                "message": f"High risk priority score ({app.risk_score:.0f}/100) computed for {app.institution_name}. Manual review recommended."
            })

        # 2. Critical & Defect Findings Alerts (Deduplicated by finding ID & defect category)
        for f in findings:
            if f.extracted_value == "MISSING" or "missing" in f.plain_reason.lower():
                alerts_to_create.append({
                    "id": f"ALT-MISSING-{app_id}-{f.rule_id}",
                    "app_id": app_id,
                    "inst_name": app.institution_name,
                    "severity": f.severity,
                    "type": "missing_doc",
                    "message": f"Mandatory submission deficiency: {f.plain_reason}"
                })
            elif "expired" in f.plain_reason.lower():
                alerts_to_create.append({
                    "id": f"ALT-EXPIRY-{app_id}-{f.rule_id}",
                    "app_id": app_id,
                    "inst_name": app.institution_name,
                    "severity": f.severity,
                    "type": "expiry_soon",
                    "message": f"Statutory certificate expired: {f.plain_reason}"
                })
            elif "photo" in f.rule_id.lower() or "infr" in f.rule_id.lower() or "fingerprints" in f.plain_reason.lower():
                alerts_to_create.append({
                    "id": f"ALT-INFRA-{app_id}-{f.rule_id}",
                    "app_id": app_id,
                    "inst_name": app.institution_name,
                    "severity": f.severity,
                    "type": "infra_gap",
                    "message": f"Infrastructure evidence defect: {f.plain_reason}"
                })
            elif f.severity == "Critical":
                alerts_to_create.append({
                    "id": f"ALT-FND-{f.id}",
                    "app_id": app_id,
                    "inst_name": app.institution_name,
                    "severity": "Critical",
                    "type": "anomaly_flag",
                    "message": f"Critical discrepancy flagged under {f.rule_id}: {f.plain_reason}"
                })

        # 3. Pending / Unresolved Verifications
        for v in verifications:
            if v.status in {"PENDING", "SOURCE_UNAVAILABLE", "MANUAL_REVIEW_REQUIRED"}:
                alerts_to_create.append({
                    "id": f"ALT-VERIF-{v.id}",
                    "app_id": app_id,
                    "inst_name": app.institution_name,
                    "severity": "Major",
                    "type": "verification_pending",
                    "message": f"Issuer verification for {v.reference_no} returned {v.status} via {v.adapter_name}."
                })

        # Save to DB
        created_alerts = []
        for a_data in alerts_to_create:
            existing = db.query(Alert).filter(Alert.id == a_data["id"]).first()
            if not existing:
                alt = Alert(
                    id=a_data["id"],
                    application_id=a_data["app_id"],
                    institution_name=a_data["inst_name"],
                    severity=a_data["severity"],
                    alert_type=a_data["type"],
                    message=a_data["message"],
                    is_read=False
                )
                db.add(alt)
                created_alerts.append(a_data)

                # Append to simulated email log
                AlertService._log_simulated_email(a_data)

        db.commit()
        return created_alerts

    @staticmethod
    def _log_simulated_email(alert_data: Dict[str, Any]):
        os.makedirs(os.path.dirname(SIMULATED_EMAIL_LOG_PATH), exist_ok=True)
        emails = []
        if os.path.exists(SIMULATED_EMAIL_LOG_PATH):
            try:
                with open(SIMULATED_EMAIL_LOG_PATH, "r") as f:
                    emails = json.load(f)
            except Exception:
                emails = []

        emails.append({
            "timestamp": datetime.utcnow().isoformat(),
            "to": "scrutiny.committee@aicte-india.org",
            "subject": f"[AICTE SmartVerify ALERT] [{alert_data['severity'].upper()}] {alert_data['type']} - {alert_data['inst_name']}",
            "body": alert_data["message"],
            "application_id": alert_data["app_id"]
        })

        with open(SIMULATED_EMAIL_LOG_PATH, "w") as f:
            json.dump(emails[-100:], f, indent=2)

    @staticmethod
    def get_simulated_emails() -> List[Dict[str, Any]]:
        if os.path.exists(SIMULATED_EMAIL_LOG_PATH):
            try:
                with open(SIMULATED_EMAIL_LOG_PATH, "r") as f:
                    return json.load(f)
            except Exception:
                return []
        return []
