import os
import json
import hashlib
import threading
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy.orm import Session
from app.models.entities import AuditLog

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
_audit_lock = threading.Lock()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT_PATH = os.path.join(BASE_DIR, "..", "..", "..", "data", "audit_checkpoint.json")

def calculate_log_hash(prev_hash: str, timestamp_str: str, actor_id: str, actor_role: str, action: str, target_id: str, details_json: str) -> str:
    raw = f"{prev_hash}|{timestamp_str}|{actor_id}|{actor_role}|{action}|{target_id}|{details_json}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class AuditService:
    @staticmethod
    def record_event(
        db: Session,
        actor_id: str,
        actor_role: str,
        action: str,
        target_type: str,
        target_id: str,
        details: Dict[str, Any]
    ) -> AuditLog:
        with _audit_lock:
            # Get the most recent log for chaining
            last_log = db.query(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).first()
            prev_hash = last_log.current_hash if last_log else GENESIS_HASH

            now = datetime.utcnow()
            timestamp_str = now.isoformat()
            # Canonical JSON serialization
            details_str = json.dumps(details or {}, sort_keys=True, separators=(',', ':'))

            current_hash = calculate_log_hash(
                prev_hash=prev_hash,
                timestamp_str=timestamp_str,
                actor_id=actor_id,
                actor_role=actor_role,
                action=action,
                target_id=target_id,
                details_json=details_str
            )

            log_id = f"AUD-{now.strftime('%Y%m%d%H%M%S')}-{current_hash[:8]}"
            log_entry = AuditLog(
                id=log_id,
                timestamp=now,
                actor_id=actor_id,
                actor_role=actor_role,
                action=action,
                target_type=target_type,
                target_id=target_id,
                details=details,
                prev_hash=prev_hash,
                current_hash=current_hash
            )
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)

            # Persist external checkpoint of head hash and committed count
            try:
                total_count = db.query(AuditLog).count()
                AuditService.write_checkpoint(current_hash, total_count)
            except Exception:
                pass

            return log_entry

    @staticmethod
    def write_checkpoint(head_hash: str, block_count: int):
        os.makedirs(os.path.dirname(CHECKPOINT_PATH), exist_ok=True)
        with open(CHECKPOINT_PATH, "w") as f:
            json.dump({
                "head_hash": head_hash,
                "block_count": block_count,
                "last_updated": datetime.utcnow().isoformat()
            }, f, indent=2)

    @staticmethod
    def read_checkpoint() -> Optional[Dict[str, Any]]:
        if os.path.exists(CHECKPOINT_PATH):
            try:
                with open(CHECKPOINT_PATH, "r") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    @staticmethod
    def verify_chain_integrity(db: Session) -> Tuple[bool, int, List[str]]:
        """
        Traverses hash chain from genesis to head and verifies continuity and external checkpoint.
        Returns: (is_valid, total_checked, errors)
        """
        with _audit_lock:
            logs = db.query(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()).all()
            if not logs:
                return True, 0, []

            expected_prev = GENESIS_HASH
            errors = []

            for idx, entry in enumerate(logs):
                if entry.prev_hash != expected_prev:
                    errors.append(f"Chain break at record #{idx} (ID: {entry.id}): prev_hash {entry.prev_hash} != expected {expected_prev}")
                
                # Recalculate hash with canonical JSON
                timestamp_str = entry.timestamp.isoformat()
                details_str = json.dumps(entry.details or {}, sort_keys=True, separators=(',', ':'))
                recalc = calculate_log_hash(
                    prev_hash=entry.prev_hash,
                    timestamp_str=timestamp_str,
                    actor_id=entry.actor_id,
                    actor_role=entry.actor_role,
                    action=entry.action,
                    target_id=entry.target_id,
                    details_json=details_str
                )
                if recalc != entry.current_hash:
                    errors.append(f"Hash tampering detected at record #{idx} (ID: {entry.id}): computed {recalc} != stored {entry.current_hash}")

                expected_prev = entry.current_hash

            # External checkpoint validation for tail deletion detection
            if os.path.exists(CHECKPOINT_PATH):
                try:
                    with open(CHECKPOINT_PATH, "r") as f:
                        checkpoint = json.load(f)
                    
                    cp_count = checkpoint.get("block_count", 0)
                    cp_head = checkpoint.get("head_hash")

                    if len(logs) < cp_count:
                        errors.append(f"Tail deletion detected: audit ledger contains {len(logs)} records, but external checkpoint confirms {cp_count} blocks.")
                    if cp_head and logs and logs[-1].current_hash != cp_head:
                        errors.append(f"Head divergence or tail deletion detected: ledger head {logs[-1].current_hash} != checkpoint head {cp_head}")
                except Exception as e:
                    pass

            is_valid = len(errors) == 0
            return is_valid, len(logs), errors
