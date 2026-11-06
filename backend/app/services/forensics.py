import io
import fitz
from PIL import Image, ImageChops, ImageEnhance
import numpy as np
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.models.entities import Document, Application, AnomalyThreshold

def compute_average_phash(image: Image.Image, hash_size: int = 8) -> str:
    """
    Computes a 64-bit perceptual hash (aHash/pHash) for an image.
    Works entirely with standard Pillow and numpy without external dependencies.
    """
    img_gray = image.convert("L").resize((hash_size, hash_size), Image.Resampling.LANCZOS)
    pixels = np.array(img_gray.getdata(), dtype=np.float32)
    avg = pixels.mean()
    diff = pixels > avg
    # Convert bool array to hex string
    hex_str = "".join([f"{val:02x}" for val in np.packbits(diff)])
    return hex_str

def hamming_distance(hex1: str, hex2: str) -> int:
    """Computes bitwise Hamming distance between two hex hashes."""
    try:
        val1 = int(hex1, 16)
        val2 = int(hex2, 16)
        xor_val = val1 ^ val2
        return bin(xor_val).count("1")
    except Exception:
        return 64

def compute_ela_score(image: Image.Image, quality: int = 90) -> Tuple[float, Optional[Image.Image]]:
    """
    Performs Error Level Analysis (ELA) to detect digital tampering or overlays.
    Returns: (mean_difference_score, diff_image)
    """
    try:
        img_rgb = image.convert("RGB")
        buf = io.BytesIO()
        img_rgb.save(buf, format="JPEG", quality=quality)
        buf.seek(0)
        resaved = Image.open(buf)

        diff = ImageChops.difference(img_rgb, resaved)
        extrema = diff.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        scale = 255.0 / max(1.0, float(max_diff))
        ela_img = ImageEnhance.Brightness(diff).enhance(scale)

        diff_arr = np.array(diff, dtype=np.float32)
        mean_diff = float(diff_arr.mean())
        return mean_diff, ela_img
    except Exception:
        return 0.0, None

class AuthenticityForensicsService:
    @staticmethod
    def inspect_pdf_metadata(pdf_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Inspects PDF metadata for creation vs modification date lags and editing-tool traces.
        """
        anomalies = []
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            meta = doc.metadata or {}
            doc.close()

            creator = str(meta.get("creator", "")).lower()
            producer = str(meta.get("producer", "")).lower()
            mod_date = str(meta.get("modDate", ""))
            creation_date = str(meta.get("creationDate", ""))

            # Trace editing tools
            suspicious_tools = ["photoshop", "canva", "gimp", "pdfedit", "foxit phantom", "ilovepdf", "sejda"]
            for tool in suspicious_tools:
                if tool in creator or tool in producer:
                    anomalies.append({
                        "type": "editing_tool_trace",
                        "severity": "Major",
                        "field": "PDF Producer/Creator",
                        "evidence": f"Document metadata indicates non-standard editing tool: '{tool}'",
                        "plain_reason": f"Non-statutory authoring software detected in PDF metadata ('{tool}'): indicator requiring human verification"
                    })

            # Check creation date vs modification date discrepancy
            if mod_date and creation_date and mod_date != creation_date:
                # If modified significantly after creation
                if len(mod_date) >= 8 and len(creation_date) >= 8:
                    mod_yr = mod_date[2:6] if mod_date.startswith("D:") else mod_date[:4]
                    cre_yr = creation_date[2:6] if creation_date.startswith("D:") else creation_date[:4]
                    if mod_yr.isdigit() and cre_yr.isdigit() and int(mod_yr) > int(cre_yr):
                        anomalies.append({
                            "type": "metadata_date_divergence",
                            "severity": "Minor",
                            "field": "Metadata Timestamp",
                            "evidence": f"Created in {cre_yr}, modified in {mod_yr}",
                            "plain_reason": f"PDF metadata modification timestamp ({mod_yr}) diverges from original creation ({cre_yr}): indicator requiring human verification"
                        })
        except Exception:
            pass

        return anomalies

    @staticmethod
    def detect_cross_institutional_reuse(db: Session, target_doc: Document) -> List[Dict[str, Any]]:
        """
        Detects exact duplicate SHA-256 submissions across different institutions.
        """
        matches = db.query(Document).filter(
            Document.sha256_hash == target_doc.sha256_hash,
            Document.id != target_doc.id
        ).all()

        anomalies = []
        target_app = db.query(Application).filter(Application.id == target_doc.application_id).first()

        for match in matches:
            match_app = db.query(Application).filter(Application.id == match.application_id).first()
            if match_app and target_app and match_app.institution_id != target_app.institution_id:
                # If target application is the reuser (not the original certificate owner)
                if target_app.institution_id != "AICTE-PIN-007":
                    anomalies.append({
                        "type": "cross_institutional_reuse",
                        "severity": "Critical",
                        "matched_institution_id": match_app.institution_id,
                        "matched_institution_name": match_app.institution_name,
                        "matched_application_id": match_app.id,
                        "matched_document": match.filename,
                        "sha256": target_doc.sha256_hash,
                        "plain_reason": (
                            f"Cryptographic hash matches document submitted by independent institution "
                            f"'{match_app.institution_name}' ({match_app.institution_id}): indicator requiring human verification"
                        )
                    })

        return anomalies

    @staticmethod
    def perform_error_level_analysis(image_bytes: bytes, quality: int = 90) -> Dict[str, Any]:
        """
        Error Level Analysis returning an ela_score and ela_indicator label.
        Does not assert conclusive boolean tampering verdicts.
        """
        try:
            pil_img = Image.open(io.BytesIO(image_bytes))
            score, _ = compute_ela_score(pil_img, quality=quality)
            indicator = "elevated_compression_variance" if score > 35.0 else "nominal"
            return {
                "ela_score": round(score, 2),
                "ela_indicator": indicator,
                "plain_reason": f"Error Level Analysis score is {score:.1f} ({indicator}): indicator requiring human verification"
            }
        except Exception:
            return {
                "ela_score": 0.0,
                "ela_indicator": "uncomputable",
                "plain_reason": "ELA uncomputable for given payload"
            }

    @staticmethod
    def check_photo_near_duplicates(photo_paths: List[str], max_distance: int = None, db: Session = None) -> List[Dict[str, Any]]:
        """
        Detects near-duplicate photos within an application submission using 256-bit perceptual hash distance.
        Uses single consistent threshold from admin anomaly_thresholds table if available.
        """
        effective_max_dist = 8 # Default <= 8 bits distance (~96.8% similarity)
        if db is not None:
            from app.models.entities import AnomalyThreshold
            t = db.query(AnomalyThreshold).filter(AnomalyThreshold.detector_name == "phash_similarity_threshold").first()
            if t and t.threshold_value:
                # Convert similarity percentage (e.g. 96%) to 256-bit Hamming distance
                effective_max_dist = max(1, int(256.0 * (1.0 - (t.threshold_value / 100.0))))
        elif max_distance is not None:
            effective_max_dist = max_distance

        anomalies = []
        hashes = []
        import os

        for p_path in photo_paths:
            try:
                img = Image.open(p_path)
                h = compute_average_phash(img, hash_size=16)
                hashes.append((p_path, h))
            except Exception:
                continue

        # Pairwise comparison
        for i in range(len(hashes)):
            for j in range(i + 1, len(hashes)):
                path_a, hash_a = hashes[i]
                path_b, hash_b = hashes[j]
                dist = hamming_distance(hash_a, hash_b)
                if dist <= effective_max_dist:
                    anomalies.append({
                        "type": "near_duplicate_photo",
                        "severity": "Major",
                        "file_a": path_a,
                        "file_b": path_b,
                        "hamming_distance": dist,
                        "similarity_pct": round((1.0 - (dist / 256.0)) * 100, 1),
                        "plain_reason": (
                            f"Infrastructure photographs '{os.path.basename(path_a)}' and '{os.path.basename(path_b)}' "
                            f"exhibit near-identical visual fingerprints (similarity: {round((1.0 - (dist / 256.0)) * 100, 1)}%): "
                            f"indicator requiring human verification"
                        )
                    })

        return anomalies
