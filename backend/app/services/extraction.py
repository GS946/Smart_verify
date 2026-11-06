import re
import io
import fitz
from PIL import Image
from datetime import datetime
from typing import Dict, Any, List, Optional

# Regex patterns for field detection
DATE_PATTERNS = [
    r'(\d{4}[\-/]\d{2}[\-/]\d{2})',        # 2026-06-30 or 2026/06/30
    r'(\d{2}[\-/]\d{2}[\-/]\d{4})',        # 30-06-2026 or 30/06/2026
    r'(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s,]+\d{4})'
]

INST_ID_PATTERN = r'(AICTE\-[A-Z0-9]{3,5}\-[0-9]{3,4})'
CERT_NO_PATTERNS = [
    r'(?:Certificate|Reg|NOC|Order|Ref|TXN)\s*(?:No|Number|#)?[:\s]+([A-Z0-9\-_/]+)',
    r'([A-Z]{2,4}\-[A-Z]{2,6}\-[0-9]{4}\-[0-9]+)'
]
INTAKE_PATTERNS = [
    r'(?:Intake|Capacity|Seats|Sanctioned)\s*(?:Approved|Declared)?[:\s]+(\d{2,4})',
    r'(\d{2,4})\s*(?:Seats|Students)'
]

def parse_date_to_iso(date_str: str) -> Optional[str]:
    if not date_str:
        return None
    cleaned = date_str.strip().strip(",.")
    # Format: YYYY-MM-DD
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y", "%d %b %Y", "%d %B %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(cleaned, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None

class DocumentIntelligenceService:
    @staticmethod
    def classify_document(text: str) -> str:
        """
        Classifies document strictly from text content keywords.
        Does not use filename hints.
        """
        text_lower = text.lower()

        if "fire" in text_lower or "fire safety" in text_lower or "fire service" in text_lower:
            return "NOC-Fire"
        elif "affiliat" in text_lower or "university" in text_lower or "affiliation order" in text_lower:
            return "NOC-Affiliating University"
        elif "accredit" in text_lower or "national board of accreditation" in text_lower or "nba" in text_lower or "naac" in text_lower:
            return "Accreditation certificate"
        elif "treasury" in text_lower or "ter " in text_lower or "payment receipt" in text_lower or "technical education regulatory" in text_lower:
            return "TER payment receipt"
        elif "state govt" in text_lower or "directorate of technical" in text_lower or "concurrence" in text_lower:
            return "NOC-State Govt"
        elif "building plan" in text_lower or "occupancy certificate" in text_lower or "structural stability" in text_lower or "built-up" in text_lower:
            return "Building plan"
        elif "faculty" in text_lower or "assistant professor" in text_lower or "teaching staff" in text_lower:
            return "Faculty list"
        elif "affidavit" in text_lower or "oath" in text_lower or "notary" in text_lower:
            return "Affidavit"
        elif "undertaking" in text_lower:
            return "Undertaking"
        return "Supporting document"

    @classmethod
    def extract_from_pdf_stream(cls, pdf_bytes: bytes, filename: str = "") -> Dict[str, Any]:
        """
        Extracts structured text, word blocks with bounding boxes, dates, IDs, and metadata from PDF.
        Includes automated Tesseract OCR fallback (eng+hin) for scanned and raster-only PDF documents.
        """
        import pytesseract
        from PIL import Image
        import io

        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        total_pages = len(doc)
        full_text = []
        bounding_boxes = []

        for page_idx in range(total_pages):
            page = doc[page_idx]
            page_w, page_h = page.rect.width, page.rect.height
            text = page.get_text("text")

            # OCR Fallback for scanned / noisy / raster PDF pages
            if not text or len(text.strip()) < 20:
                try:
                    pix = page.get_pixmap(dpi=150)
                    img_data = pix.tobytes("png")
                    pil_img = Image.open(io.BytesIO(img_data))

                    # Run Tesseract OCR (with bilingual English + Hindi support)
                    try:
                        ocr_text = pytesseract.image_to_string(pil_img, lang="eng+hin")
                    except Exception:
                        ocr_text = pytesseract.image_to_string(pil_img, lang="eng")

                    text = ocr_text

                    # Extract block & word bounding boxes from OCR
                    ocr_data = pytesseract.image_to_data(pil_img, output_type=pytesseract.Output.DICT)
                    scale_x = page_w / max(1.0, float(pix.width))
                    scale_y = page_h / max(1.0, float(pix.height))
                    n_boxes = len(ocr_data.get('text', []))
                    for i in range(n_boxes):
                        word = ocr_data['text'][i].strip()
                        if word:
                            x0 = float(ocr_data['left'][i]) * scale_x
                            y0 = float(ocr_data['top'][i]) * scale_y
                            w = float(ocr_data['width'][i]) * scale_x
                            h = float(ocr_data['height'][i]) * scale_y
                            bounding_boxes.append({
                                "page": page_idx + 1,
                                "text": word,
                                "bbox": {
                                    "x": round(x0, 1),
                                    "y": round(y0, 1),
                                    "w": round(w, 1),
                                    "h": round(h, 1),
                                    "page_w": round(page_w, 1),
                                    "page_h": round(page_h, 1)
                                }
                            })
                except Exception:
                    pass
            else:
                # Text-layer Block-level extraction
                blocks = page.get_text("blocks")
                for b in blocks:
                    if len(b) >= 5 and b[4].strip():
                        x0, y0, x1, y1, btext = b[0], b[1], b[2], b[3], b[4].strip()
                        bounding_boxes.append({
                            "page": page_idx + 1,
                            "text": btext,
                            "bbox": {
                                "x": round(x0, 1),
                                "y": round(y0, 1),
                                "w": round(x1 - x0, 1),
                                "h": round(y1 - y0, 1),
                                "page_w": round(page_w, 1),
                                "page_h": round(page_h, 1)
                            }
                        })

            full_text.append(text)

        doc.close()
        aggregated_text = "\n".join(full_text)

        # Document Classification from Content Only
        detected_category = cls.classify_document(aggregated_text)

        # Field Extraction Heuristics
        extracted_data = cls._parse_fields_from_blocks(bounding_boxes, aggregated_text)
        extracted_data["document_type"] = detected_category
        extracted_data["page_count"] = total_pages
        extracted_data["all_blocks"] = bounding_boxes[:30] # Top 30 blocks for UI display

        return extracted_data

    @classmethod
    def _parse_fields_from_blocks(cls, blocks: List[Dict[str, Any]], full_text: str) -> Dict[str, Any]:
        result = {
            "institution_name": None,
            "institution_id": None,
            "certificate_number": None,
            "issue_date": None,
            "validity_date": None,
            "declared_intake": None,
            "provenance": {}
        }

        # 1. Institution ID
        inst_id_match = re.search(INST_ID_PATTERN, full_text)
        if inst_id_match:
            result["institution_id"] = inst_id_match.group(1)

        # 2. Iterate blocks for localized field provenance
        for blk in blocks:
            btext = blk["text"]
            b_box = blk["bbox"]
            p_num = blk["page"]

            # Institution Name
            if "Name of Institution:" in btext or "Institution:" in btext:
                parts = btext.split(":")
                if len(parts) > 1:
                    name_val = parts[1].split("\n")[0].strip()
                    if name_val and not result["institution_name"]:
                        result["institution_name"] = name_val
                        result["provenance"]["institution_name"] = {"page": p_num, "bbox": b_box, "raw": name_val}

            # Certificate Number
            if "Certificate" in btext or "Reg No" in btext or "TXN" in btext or "NOC" in btext:
                for pat in CERT_NO_PATTERNS:
                    m = re.search(pat, btext)
                    if m and not result["certificate_number"]:
                        cert_val = m.group(1).strip()
                        result["certificate_number"] = cert_val
                        result["provenance"]["certificate_number"] = {"page": p_num, "bbox": b_box, "raw": cert_val}
                        break

            # Dates
            if "Issuance Date:" in btext or "Issue Date" in btext or "Issued:" in btext:
                for dp in DATE_PATTERNS:
                    dm = re.search(dp, btext)
                    if dm and not result["issue_date"]:
                        iso_d = parse_date_to_iso(dm.group(1))
                        result["issue_date"] = iso_d or dm.group(1)
                        result["provenance"]["issue_date"] = {"page": p_num, "bbox": b_box, "raw": dm.group(1)}
                        break

            if "Validity" in btext or "Expiration" in btext or "Valid Until" in btext:
                for dp in DATE_PATTERNS:
                    dm = re.search(dp, btext)
                    if dm and not result["validity_date"]:
                        iso_d = parse_date_to_iso(dm.group(1))
                        result["validity_date"] = iso_d or dm.group(1)
                        result["provenance"]["validity_date"] = {"page": p_num, "bbox": b_box, "raw": dm.group(1)}
                        break

            # Intake
            if "Intake" in btext or "Seats" in btext:
                for ip in INTAKE_PATTERNS:
                    im = re.search(ip, btext)
                    if im and not result["declared_intake"]:
                        result["declared_intake"] = int(im.group(1))
                        result["provenance"]["declared_intake"] = {"page": p_num, "bbox": b_box, "raw": im.group(1)}
                        break

        return result
