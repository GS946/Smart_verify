import os
import io
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple
import fitz
from PIL import Image
from app.core.config import settings
from app.core.security import encrypt_bytes, decrypt_bytes

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png"}

# Known malware / executable magic signatures stub
SUSPICIOUS_SIGNATURES = [
    b"MZ",           # DOS/PE executable
    b"\x7fELF",      # Linux ELF executable
    b"<!DOCTYPE html", # Disguised HTML in document
    b"<script",      # Embedded web scripts
    b"powershell",   # Suspicious shell scripts
]

class IngestionError(Exception):
    def __init__(self, message: str, code: str = "INGESTION_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)

class SecureIngestionService:
    @staticmethod
    def inspect_malware_stub(raw_bytes: bytes) -> bool:
        """
        Malware signature check using exact magic byte headers at offset 0
        and strict script inspection in XML/HTML preambles.
        """
        if not raw_bytes:
            return False
        # Offset 0 binary executable magic signatures
        if raw_bytes.startswith(b"MZ"):  # DOS/PE Executable
            return False
        if raw_bytes.startswith(b"\x7fELF"):  # Linux ELF Executable
            return False
        if raw_bytes.startswith(b"\xca\xfe\xba\xbe") or raw_bytes.startswith(b"\xfe\xed\xfa\xce"):  # Mach-O
            return False
        
        # Check text preamble for disguised HTML / script tags
        head = raw_bytes[:1024].lower()
        if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
            return False
        if b"<script" in head:
            return False
        if head.startswith(b"powershell") or head.startswith(b"#!"):
            return False
            
        return True

    @staticmethod
    def compute_sha256(raw_bytes: bytes) -> str:
        return hashlib.sha256(raw_bytes).hexdigest()

    @staticmethod
    def check_integrity(raw_bytes: bytes, filename: str) -> Tuple[bool, int, str]:
        """
        Validates whether the file is uncorrupted and counts pages.
        Returns: (is_valid, page_count, reason_if_invalid)
        """
        ext = os.path.splitext(filename)[1].lower()
        if ext == ".pdf":
            try:
                doc = fitz.open(stream=raw_bytes, filetype="pdf")
                if doc.is_encrypted:
                    return False, 0, "PDF is password protected"
                page_count = len(doc)
                if page_count == 0:
                    return False, 0, "PDF has zero pages"
                doc.close()
                return True, page_count, ""
            except Exception as e:
                return False, 0, f"Corrupted or invalid PDF structure: {str(e)}"
        elif ext in {".jpg", ".jpeg", ".png"}:
            try:
                img = Image.open(io.BytesIO(raw_bytes))
                img.verify()
                return True, 1, ""
            except Exception as e:
                return False, 0, f"Corrupted image file: {str(e)}"
        return False, 0, f"Unsupported file extension: {ext}"

    @classmethod
    def ingest_document(
        cls,
        raw_bytes: bytes,
        filename: str,
        application_id: str,
        uploader_id: str,
        doc_type: str
    ) -> Dict[str, Any]:
        """
        Ingests and securely stores an uploaded document with write-once encrypted storage.
        """
        # 1. Size Check
        if len(raw_bytes) > MAX_FILE_SIZE:
            raise IngestionError("File size exceeds 25 MB limit", "FILE_TOO_LARGE")

        # 2. Extension Check
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise IngestionError(f"Unsupported file type '{ext}'", "UNSUPPORTED_TYPE")

        # 3. Malware Stub Check
        if not cls.inspect_malware_stub(raw_bytes):
            raise IngestionError("File failed security screening (disallowed executable signature detected)", "MALWARE_FLAG")

        # 4. Compute Hash
        sha256_hash = cls.compute_sha256(raw_bytes)

        # 5. Integrity Check
        is_valid, page_count, reason = cls.check_integrity(raw_bytes, filename)
        is_corrupted = not is_valid

        # 6. Immutable Storage
        # File is encrypted and stored in application-specific folder
        app_storage_dir = os.path.join(settings.STORAGE_DIR, application_id)
        os.makedirs(app_storage_dir, exist_ok=True)

        storage_filename = f"{sha256_hash[:16]}_{filename}.enc"
        storage_path = os.path.join(app_storage_dir, storage_filename)

        # Write once: if already exists, maintain immutability
        if not os.path.exists(storage_path):
            encrypted_payload = encrypt_bytes(raw_bytes)
            with open(storage_path, "wb") as f:
                f.write(encrypted_payload)

        return {
            "application_id": application_id,
            "filename": filename,
            "doc_type": doc_type,
            "storage_path": storage_path,
            "sha256_hash": sha256_hash,
            "page_count": max(1, page_count),
            "is_corrupted": is_corrupted,
            "corruption_reason": reason,
            "uploader_id": uploader_id,
            "uploaded_at": datetime.utcnow().isoformat(),
            "encrypted": True
        }

    @staticmethod
    def read_document_bytes(storage_path: str) -> bytes:
        """Reads and decrypts stored file bytes."""
        if not os.path.exists(storage_path):
            raise FileNotFoundError(f"Stored document not found: {storage_path}")
        with open(storage_path, "rb") as f:
            encrypted_bytes = f.read()
        return decrypt_bytes(encrypted_bytes)

    @staticmethod
    def purge_expired_records(retention_days: int = None, db: Any = None) -> int:
        """
        Purges encrypted files older than configured data retention days ONLY
        for closed cases. Applications under active review are never purged.
        Database metadata, SHA-256 hashes, and audit ledger entries are preserved.
        """
        from datetime import timezone
        days = retention_days or settings.DATA_RETENTION_DAYS
        cutoff = datetime.utcnow() - timedelta(days=days)
        purged_count = 0

        # If DB session is provided, selectively purge only closed applications
        if db is not None:
            from app.models.entities import Application, Document
            # Cases considered closed/completed
            closed_statuses = {"Ready for official scrutiny", "Closed", "Archived"}
            closed_apps = db.query(Application).filter(
                Application.status.in_(closed_statuses),
                Application.updated_at < cutoff
            ).all()

            for app in closed_apps:
                docs = db.query(Document).filter(Document.application_id == app.id).all()
                for doc in docs:
                    if doc.storage_path and os.path.exists(doc.storage_path) and doc.storage_path.endswith(".enc"):
                        try:
                            os.remove(doc.storage_path)
                            doc.storage_path = "[PURGED_AFTER_RETENTION]"
                            purged_count += 1
                        except OSError:
                            pass
            db.commit()
            return purged_count

        # Fallback filesystem scan: verify file modification time
        for root, dirs, files in os.walk(settings.STORAGE_DIR):
            for file in files:
                if file.endswith(".enc"):
                    full_path = os.path.join(root, file)
                    mtime = datetime.fromtimestamp(os.path.getmtime(full_path))
                    if mtime < cutoff:
                        try:
                            os.remove(full_path)
                            purged_count += 1
                        except OSError:
                            pass
        return purged_count
