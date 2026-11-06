from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.entities import Application, Document, Finding, BaselineRecord, Institution

class ClaimToEvidenceGraphService:
    @staticmethod
    def build_application_graph(db: Session, app_id: str) -> Dict[str, Any]:
        """
        Constructs a claim-to-evidence knowledge graph for an application.
        Nodes represent Institutions, Applications, Documents, Baseline Records, and Claims.
        Edges represent relationships; red/conflicted edges represent rule violations or discrepancies.
        """
        app = db.query(Application).filter(Application.id == app_id).first()
        if not app:
            return {"nodes": [], "edges": []}

        inst = db.query(Institution).filter(Institution.id == app.institution_id).first()
        baseline = db.query(BaselineRecord).filter(BaselineRecord.institution_id == app.institution_id).first()
        docs = db.query(Document).filter(Document.application_id == app_id).all()
        findings = db.query(Finding).filter(Finding.application_id == app_id).all()

        nodes = []
        edges = []

        # 1. Institution Root Node
        nodes.append({
            "id": f"inst-{app.institution_id}",
            "label": inst.name if inst else app.institution_id,
            "type": "institution",
            "category": "root",
            "status": "normal"
        })

        # 2. Application Node
        app_has_critical = any(f.severity == "Critical" for f in findings)
        nodes.append({
            "id": f"app-{app.id}",
            "label": f"Application {app.id}\n({app.category})",
            "type": "application",
            "category": "core",
            "status": "conflict" if app_has_critical else "normal"
        })
        edges.append({
            "source": f"inst-{app.institution_id}",
            "target": f"app-{app.id}",
            "label": "submits",
            "status": "valid"
        })

        # 3. AICTE Central Baseline Record Node
        if baseline:
            nodes.append({
                "id": f"baseline-{app.institution_id}",
                "label": f"AICTE Central Baseline\nApproved Seats: {baseline.approved_intake}\nTER: {baseline.ter_payment_status}",
                "type": "baseline_record",
                "category": "authorized_record",
                "status": "normal"
            })
            edges.append({
                "source": f"inst-{app.institution_id}",
                "target": f"baseline-{app.institution_id}",
                "label": "records_on_file",
                "status": "valid"
            })

        # 4. Declared Intake Claim Node
        intake_conflict = any(f.rule_id == "RULE-CROSS-INTK-003" for f in findings)
        nodes.append({
            "id": f"claim-intake-{app.id}",
            "label": f"Declared Intake: {app.declared_intake} seats",
            "type": "claim",
            "category": "claim",
            "status": "conflict" if intake_conflict else "valid"
        })
        edges.append({
            "source": f"app-{app.id}",
            "target": f"claim-intake-{app.id}",
            "label": "declares",
            "status": "valid"
        })

        if baseline:
            edges.append({
                "source": f"claim-intake-{app.id}",
                "target": f"baseline-{app.institution_id}",
                "label": "intake_mismatch" if intake_conflict else "intake_matches",
                "status": "conflict" if intake_conflict else "valid",
                "is_conflict": intake_conflict
            })

        # 5. Document Nodes
        for d in docs:
            doc_findings = [f for f in findings if f.document_id == d.id or f.source_document == d.filename]
            is_doc_conflict = len(doc_findings) > 0

            nodes.append({
                "id": f"doc-{d.id}",
                "label": f"{d.doc_type}\n({d.filename})",
                "type": "document",
                "category": "statutory_evidence",
                "status": "conflict" if is_doc_conflict else "valid"
            })

            edges.append({
                "source": f"app-{app.id}",
                "target": f"doc-{d.id}",
                "label": "attaches",
                "status": "conflict" if is_doc_conflict else "valid",
                "is_conflict": is_doc_conflict
            })

        # 6. TER Payment Claim Node
        ter_conflict = any(f.rule_id == "RULE-PAY-TER-004" for f in findings)
        nodes.append({
            "id": f"claim-ter-{app.id}",
            "label": f"TER Payment Status\n(Declared in Application)",
            "type": "claim",
            "category": "claim",
            "status": "conflict" if ter_conflict else "valid"
        })
        edges.append({
            "source": f"app-{app.id}",
            "target": f"claim-ter-{app.id}",
            "label": "claims_payment",
            "status": "valid"
        })
        if baseline:
            edges.append({
                "source": f"claim-ter-{app.id}",
                "target": f"baseline-{app.institution_id}",
                "label": "unpaid_or_pending" if ter_conflict else "payment_confirmed",
                "status": "conflict" if ter_conflict else "valid",
                "is_conflict": ter_conflict
            })

        # 7. Faculty Cadre & Ratio Claim Node (backed by RULE-FACULTY-RATIO-009)
        faculty_conflict = any(f.rule_id == "RULE-FACULTY-RATIO-009" for f in findings)
        nodes.append({
            "id": f"claim-faculty-{app.id}",
            "label": f"Cadre & Faculty Ratio (20:1)\n(Declared in Application)",
            "type": "claim",
            "category": "claim",
            "status": "conflict" if faculty_conflict else "valid"
        })
        edges.append({
            "source": f"app-{app.id}",
            "target": f"claim-faculty-{app.id}",
            "label": "declares_cadre",
            "status": "conflict" if faculty_conflict else "valid",
            "is_conflict": faculty_conflict
        })

        return {
            "application_id": app_id,
            "nodes": nodes,
            "edges": edges,
            "total_conflicts": sum(1 for e in edges if e.get("is_conflict"))
        }
