"""
AICTE SmartVerify AI - Synthetic Data Generator
Generates:
- 40 Fictional Institutions & Applications across 3 categories
- Multi-page synthetic PDF documents with text layers, Hindi headers, and signed QR codes
- Baseline AICTE Central Records (for cross-record matching)
- Injected defects recorded in data/ground_truth.json
- HERO SCENARIO: "Sunrise Institute of Technology"
"""

import os
import io
import json
import random
import hashlib
from datetime import datetime, timedelta
import fitz  # PyMuPDF
from PIL import Image, ImageDraw, ImageFilter
import qrcode
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Fixed seed for reproducibility
RANDOM_SEED = 20260101
random.seed(RANDOM_SEED)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "seed_output")
DOCS_DIR = os.path.join(OUTPUT_DIR, "documents")
PHOTOS_DIR = os.path.join(OUTPUT_DIR, "photos")
os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(PHOTOS_DIR, exist_ok=True)

# 1. Generate Deterministic Key Pair for QR digital signatures
# Derive 32 bytes from fixed seed
key_seed = hashlib.sha256(b"AICTE_SMARTVERIFY_ED25519_DEMO_SEED_2026").digest()
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_seed)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pubkey_path = os.path.join(BASE_DIR, "demo_public_key.pem")
with open(pubkey_path, "wb") as f:
    f.write(public_pem)

print(f"[KeyGen] Generated deterministic demo Ed25519 public key at {pubkey_path}")

# Fictional Institutions Catalog
INSTITUTION_NAMES = [
    ("Sunrise Institute of Technology", "AICTE-SIT-001", "Dehradun, Uttarakhand"),
    ("Apex Institute of Science and Technology", "AICTE-APX-002", "Nagpur, Maharashtra"),
    ("Blue Ridge Engineering Academy", "AICTE-BRE-003", "Coimbatore, Tamil Nadu"),
    ("Cyber Crest Institute of Technology", "AICTE-CCI-004", "Bhopal, Madhya Pradesh"),
    ("Lotus Valley Engineering College", "AICTE-LVE-005", "Jaipur, Rajasthan"),
    ("Greenfield Polytechnic Institute", "AICTE-GPI-006", "Ranchi, Jharkhand"),
    ("Pioneer Institute of Technology", "AICTE-PIN-007", "Lucknow, Uttar Pradesh"),
    ("Zenith Academy of Technical Studies", "AICTE-ZAT-008", "Pune, Maharashtra"),
    ("Horizon College of Engineering", "AICTE-HCE-009", "Mysuru, Karnataka"),
    ("Silver Oak Institute of Computer Sciences", "AICTE-SOI-010", "Ahmedabad, Gujarat"),
    ("Trinity Institute of Polytechnic Studies", "AICTE-TIS-011", "Kochi, Kerala"),
    ("Starlight Engineering College", "AICTE-SEC-012", "Patna, Bihar"),
    ("Royal Crown Institute of Management & Tech", "AICTE-RCI-013", "Bhubaneswar, Odisha"),
    ("Vanguard Institute of Advanced Studies", "AICTE-VAS-014", "Chandigarh, Punjab"),
    ("Summit College of Engineering", "AICTE-SCE-015", "Shimla, Himachal Pradesh"),
    ("Orion Institute of Technology", "AICTE-OIT-016", "Guwahati, Assam"),
    ("Cascade Institute of Technical Education", "AICTE-CIE-017", "Gwalior, Madhya Pradesh"),
    ("Emerald Bay College of Engineering", "AICTE-EBC-018", "Visakhapatnam, Andhra Pradesh"),
    ("Golden Gate Polytechnic College", "AICTE-GGP-019", "Surat, Gujarat"),
    ("Harmony Institute of Technology", "AICTE-HIT-020", "Raipur, Chhattisgarh"),
    ("Meridian Institute of Technology", "AICTE-MIT-021", "Indore, Madhya Pradesh"),
    ("North Star Engineering Academy", "AICTE-NSE-022", "Jammu, J&K"),
    ("Pacific Institute of Engineering", "AICTE-PIE-023", "Mangaluru, Karnataka"),
    ("Quantum Institute of Technology", "AICTE-QIT-024", "Kolkata, West Bengal"),
    ("Radiant College of Engineering", "AICTE-RCE-025", "Varanasi, Uttar Pradesh"),
    ("Sterling Institute of Technology", "AICTE-SIT-026", "Vadodara, Gujarat"),
    ("Titan Institute of Technical Studies", "AICTE-TTS-027", "Madurai, Tamil Nadu"),
    ("Unity College of Engineering", "AICTE-UCE-028", "Amritsar, Punjab"),
    ("Valley View Institute of Science", "AICTE-VVI-029", "Dehradun, Uttarakhand"),
    ("Windsor Institute of Technology", "AICTE-WIT-030", "Nashik, Maharashtra"),
    ("Amber Valley Engineering College", "AICTE-AVE-031", "Hubballi, Karnataka"),
    ("Beacon Institute of Technology", "AICTE-BIT-032", "Agra, Uttar Pradesh"),
    ("Crestview College of Engineering", "AICTE-CCE-033", "Tiruchirappalli, Tamil Nadu"),
    ("Dynamic Institute of Technical Education", "AICTE-DIT-034", "Kota, Rajasthan"),
    ("Eagle Crest Engineering Academy", "AICTE-ECE-035", "Jabalpur, Madhya Pradesh"),
    ("Falcon Institute of Technology", "AICTE-FIT-036", "Warangal, Telangana"),
    ("Gateway Institute of Engineering", "AICTE-GIE-037", "Vijayawada, Andhra Pradesh"),
    ("Heritage College of Technology", "AICTE-HCT-038", "Jalandhar, Punjab"),
    ("Imperial Institute of Technology", "AICTE-IIT-039", "Udaipur, Rajasthan"),
    ("Jupiter Engineering Academy", "AICTE-JEA-040", "Thiruvananthapuram, Kerala"),
]

CATEGORIES = (
    ["EoA-Continuation"] * 25 +
    ["New-Programme"] * 8 +
    ["Intake-Change"] * 7
)

PROGRAMMES = [
    ("Computer Science and Engineering", "Under Graduate", 60),
    ("Electronics and Communication", "Under Graduate", 60),
    ("Mechanical Engineering", "Under Graduate", 60),
    ("Civil Engineering", "Under Graduate", 60),
    ("Information Technology", "Under Graduate", 60),
    ("Artificial Intelligence & Data Science", "Under Graduate", 60),
    ("Master of Business Administration", "Post Graduate", 60),
    ("Master of Computer Applications", "Post Graduate", 60),
]

UNIVERSITIES = [
    "State Technical University",
    "Central Technological University",
    "Apex Regional University",
    "National Technical University",
]

def make_qr_code(payload: str) -> bytes:
    qr = qrcode.QRCode(box_size=3, border=2)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def create_synthetic_pdf(
    filepath: str,
    title: str,
    hindi_title: str,
    inst_name: str,
    inst_id: str,
    doc_type: str,
    cert_no: str,
    issue_date: str,
    valid_date: str,
    qr_payload: str,
    extra_details: list,
    tampered_overlay: str = None
):
    doc = fitz.open()
    page = doc.new_page(width=595, height=842) # A4

    # Header border
    page.draw_rect(fitz.Rect(20, 20, 575, 822), color=(0.1, 0.2, 0.4), width=1.5)
    page.draw_rect(fitz.Rect(24, 24, 571, 818), color=(0.7, 0.7, 0.7), width=0.5)

    # Synthetic watermark banner
    page.insert_text(fitz.Point(35, 45), "SYNTHETIC-DEMO DOCUMENT FOR AICTE SMARTVERIFY AI", fontsize=8, color=(0.5, 0.5, 0.5))
    
    # Official Emblem / Titles
    page.insert_text(fitz.Point(120, 75), title, fontsize=14, fontname="helv", color=(0.05, 0.15, 0.35))
    page.insert_text(fitz.Point(135, 95), hindi_title, fontsize=11, fontname="helv", color=(0.2, 0.2, 0.2))
    
    # Metadata Box
    page.draw_rect(fitz.Rect(40, 115, 430, 230), fill=(0.96, 0.97, 0.99), color=(0.8, 0.85, 0.9))
    page.insert_text(fitz.Point(50, 135), f"Document Category: {doc_type}", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text(fitz.Point(50, 155), f"Certificate / Reg No: {cert_no}", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text(fitz.Point(50, 175), f"Issuance Date: {issue_date}", fontsize=10, fontname="helv", color=(0, 0, 0))
    
    if tampered_overlay:
        # Visual tampering simulation: original date faintly visible with altered overlay
        page.insert_text(fitz.Point(50, 195), f"Validity Expiration: {tampered_overlay}", fontsize=10, fontname="times-bold", color=(0.85, 0.1, 0.1))
        page.insert_text(fitz.Point(230, 195), f"[MODIFIED STAMP: {valid_date}]", fontsize=7, color=(0.6, 0.6, 0.6))
    else:
        page.insert_text(fitz.Point(50, 195), f"Validity Expiration: {valid_date}", fontsize=10, fontname="helv", color=(0, 0, 0))

    page.insert_text(fitz.Point(50, 215), f"Authority / Issuer: Competent State Directorate", fontsize=10, fontname="helv", color=(0, 0, 0))

    # Insert QR Code
    if qr_payload:
        qr_bytes = make_qr_code(qr_payload)
        page.insert_image(fitz.Rect(450, 115, 555, 220), stream=qr_bytes)
        page.insert_text(fitz.Point(455, 230), "Digitally Signed", fontsize=8, color=(0.2, 0.4, 0.2))

    # Beneficiary Details
    page.draw_rect(fitz.Rect(40, 245, 555, 310), color=(0.8, 0.8, 0.8))
    page.insert_text(fitz.Point(50, 265), "BENEFICIARY INSTITUTION DETAILS", fontsize=9, fontname="helv", color=(0.2, 0.2, 0.5))
    page.insert_text(fitz.Point(50, 285), f"Name of Institution: {inst_name}", fontsize=10, fontname="helv", color=(0, 0, 0))
    page.insert_text(fitz.Point(50, 302), f"Permanent AICTE Institute ID: {inst_id}", fontsize=9, fontname="helv", color=(0.3, 0.3, 0.3))

    # Body clauses
    y = 335
    page.insert_text(fitz.Point(50, y), "STATUTORY DECLARATION & CERTIFICATION DETAILS:", fontsize=10, fontname="helv", color=(0, 0, 0))
    y += 20
    for item in extra_details:
        page.insert_text(fitz.Point(60, y), f"• {item}", fontsize=9, fontname="helv", color=(0.1, 0.1, 0.1))
        y += 18

    # Signature block
    page.insert_text(fitz.Point(50, 750), "Authorized Signature / Digital Token", fontsize=9, fontname="helv", color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(400, 750), "Competent Authority Seal", fontsize=9, fontname="helv", color=(0.3, 0.3, 0.3))
    page.draw_line(fitz.Point(50, 740), fitz.Point(200, 740), color=(0.4, 0.4, 0.4))
    page.draw_line(fitz.Point(400, 740), fitz.Point(540, 740), color=(0.4, 0.4, 0.4))

    doc.save(filepath)
    doc.close()

def generate_synthetic_photo(filepath: str, facility_type: str, inst_name: str, blurry: bool = False, draw_seed: int = 1):
    r_tint = 200 + (draw_seed * 13) % 50
    g_tint = 200 + (draw_seed * 29) % 50
    b_tint = 200 + (draw_seed * 37) % 50
    img = Image.new("RGB", (640, 480), color=(r_tint, g_tint, b_tint))
    draw = ImageDraw.Draw(img)

    # Draw room architecture
    # Floor
    draw.polygon([(0, 320), (640, 320), (640, 480), (0, 480)], fill=((r_tint - 40)%256, (g_tint - 40)%256, (b_tint - 40)%256))
    # Wall panels
    draw.line([(0, 320), (640, 320)], fill=(160, 150, 140), width=3)
    
    # Label banner
    draw.rectangle([(20, 20), (620, 70)], fill=(20, 40, 80))
    # Synthetic stamp
    draw.text((30, 30), f"AICTE SYNTHETIC INFRASTRUCTURE EVIDENCE: {facility_type.upper()}", fill=(255, 255, 255))
    draw.text((30, 50), f"Institution: {inst_name} | Seed: {draw_seed} (Simulated)", fill=(200, 220, 255))

    # Room fixtures based strictly on facility_type
    if "Computer" in facility_type:
        for x in range(50, 580, 110):
            draw.rectangle([(x, 200), (x+80, 280)], fill=(30, 30, 30))
            draw.rectangle([(x+5, 205), (x+75, 270)], fill=(50, 180, 255))
            draw.rectangle([(x+30, 280), (x+50, 320)], fill=(70, 70, 70))
    elif "Library" in facility_type:
        for x in range(30, 610, 120):
            draw.rectangle([(x, 70), (x+90, 320)], fill=(120, 60, 20))
            for y_shelf in range(100, 310, 30):
                draw.line([(x, y_shelf), (x+90, y_shelf)], fill=(230, 200, 140), width=3)
    elif "Workshop" in facility_type:
        draw.rectangle([(0, 40), (640, 70)], fill=(220, 180, 20))
        draw.rectangle([(80, 220), (280, 340)], fill=(50, 60, 80))
        draw.rectangle([(340, 220), (560, 340)], fill=(60, 70, 90))
    else: # Classroom
        draw.rectangle([(120, 80), (520, 190)], fill=(20, 120, 30))
        draw.rectangle([(130, 90), (510, 180)], fill=(34, 139, 34))
        for x in range(60, 580, 110):
            draw.rectangle([(x, 240), (x+70, 310)], fill=(150, 110, 70))

    if blurry:
        # Apply heavy Gaussian Blur to simulate substandard/blurred submission
        img = img.filter(ImageFilter.GaussianBlur(radius=8))

    img.save(filepath, format="JPEG", quality=85)

def run_generation():
    print("[SyntheticData] Starting generation of 40 institutions and applications...")

    ground_truth = {
        "metadata": {
            "version": "1.0.0",
            "generation_date": datetime.now().isoformat(),
            "hero_institution_id": "AICTE-SIT-001",
            "total_institutions": len(INSTITUTION_NAMES),
            "baseline_assumptions": {
                "manual_review_minutes_per_app": 45,
                "ai_assisted_minutes_per_app": 8,
                "estimated_time_saving_pct": 82.2
            }
        },
        "defects": {}
    }

    mock_db = {
        "institutions": [],
        "applications": [],
        "baseline_records": [],
        "documents": [],
        "photos": []
    }

    # Pre-generate shared Fire NOC for Pioneer Institute and Sunrise Institute
    shared_fire_path = os.path.join(DOCS_DIR, "SHARED_PIONEER_FIRE_NOC.pdf")
    create_synthetic_pdf(
        filepath=shared_fire_path,
        title="STATE FIRE AND EMERGENCY SERVICES",
        hindi_title="राज्य अग्निशमन एवं आपातकालीन सेवाएं",
        inst_name="Pioneer Institute of Technology",
        inst_id="AICTE-PIN-007",
        doc_type="NOC-Fire",
        cert_no="FS-NOC-2026-PIN507",
        issue_date="2025-06-01",
        valid_date="2027-05-31",
        qr_payload="DOC:FIRE|ID:AICTE-PIN-007|CERT:FS-NOC-2026-PIN507|VALID:2027-05-31",
        extra_details=[
            "Fire safety inspection conducted as per National Building Code (Part IV).",
            "Hydrant system, hose reels, and smoke detectors certified operational.",
            "Adequate egress routes and emergency evacuation stairwells verified."
        ]
    )
    with open(shared_fire_path, "rb") as f:
        saved_fire_noc_bytes = f.read()

    for idx, (inst_name, inst_id, location) in enumerate(INSTITUTION_NAMES):
        category = CATEGORIES[idx]
        app_id = f"APP-2026-{inst_id.split('-')[1]}{idx+1:02d}"
        
        # Determine if this institution has injected defects
        is_hero = (inst_id == "AICTE-SIT-001")
        injected = []

        # Intake settings
        baseline_intake = 60
        declared_intake = 60

        if is_hero:
            declared_intake = 120 # Hero Defect 1: Declared 120 vs Baseline 60
            injected.append({
                "type": "intake_mismatch",
                "rule_id": "RULE-CROSS-INTK-003",
                "severity": "Critical",
                "declared": 120,
                "baseline": 60,
                "reason": "Declared intake of 120 seats exceeds AICTE baseline record of 60 seats without sanctioned variation"
            })
        elif idx == 10: # Defect: Another intake mismatch
            declared_intake = 180
            baseline_intake = 120
            injected.append({
                "type": "intake_mismatch",
                "rule_id": "RULE-CROSS-INTK-003",
                "severity": "Critical",
                "declared": 180,
                "baseline": 120,
                "reason": "Declared intake 180 exceeds baseline 120"
            })

        # TER Payment settings
        ter_status = "PAID"
        ter_ref = f"TER-2026-TXN{idx+1000}"
        if is_hero:
            ter_status = "PENDING" # Hero Defect 5: Unpaid TER
            injected.append({
                "type": "unpaid_ter",
                "rule_id": "RULE-PAY-TER-004",
                "severity": "Major",
                "status": "PENDING",
                "reason": "Technical Education Regulatory (TER) fee payment status is PENDING in AICTE financial database"
            })
        elif idx == 15:
            ter_status = "PENDING"
            injected.append({
                "type": "unpaid_ter",
                "rule_id": "RULE-PAY-TER-004",
                "severity": "Major",
                "status": "PENDING",
                "reason": "TER fee payment status is PENDING"
            })

        # Fire NOC settings
        fire_cert_no = f"FS-NOC-2026-{idx+500}"
        fire_issue = "2025-06-01"
        fire_valid = "2027-05-31" # Valid for 2 years
        fire_tampered = None
        
        if is_hero:
            # Hero Defect 2: Will reuse Pioneer Institute's Fire NOC or mark reuse
            # We will handle reuse file copy below
            injected.append({
                "type": "reused_statutory_doc",
                "rule_id": "RULE-ANOM-DUPDOC-006",
                "severity": "Critical",
                "reused_with": "AICTE-PIN-007",
                "reason": "Fire Safety NOC SHA-256 fingerprint matches document submitted by another institution (Pioneer Institute of Technology)"
            })
        elif idx == 20:
            # Expired Fire NOC defect
            fire_valid = "2025-12-31" # Expired
            injected.append({
                "type": "expired_document",
                "rule_id": "RULE-DOC-FIRE-001",
                "severity": "Critical",
                "doc_type": "NOC-Fire",
                "expiry_date": "2025-12-31",
                "reason": "Fire Safety NOC expired on 2025-12-31"
            })

        # Affiliation Certificate settings
        affil_cert_no = f"UNIV-AFFIL-2026-{idx+200}"
        affil_issue = "2025-07-01"
        affil_valid = "2027-06-30"
        affil_tampered = None
        if is_hero:
            # Hero Defect 3: Tampered validity date
            affil_tampered = "2027-06-30" # Altered visually to 2027
            affil_valid = "2024-06-30"    # Actually expired/signed as 2024
            injected.append({
                "type": "tampered_validity_date",
                "rule_id": "RULE-DOC-AFFL-002",
                "severity": "Critical",
                "doc_type": "NOC-Affiliating University",
                "displayed_date": "2027-06-30",
                "signed_payload_date": "2024-06-30",
                "reason": "Affiliation certificate displays 2027-06-30 but cryptographic payload confirms expiration on 2024-06-30"
            })

        # Accreditation settings
        accr_valid = "2027-12-31"
        if is_hero:
            # Hero Defect 4: Expired accreditation
            accr_valid = "2024-05-31"
            injected.append({
                "type": "expired_accreditation",
                "rule_id": "RULE-DOC-ACCR-005",
                "severity": "Major",
                "doc_type": "Accreditation certificate",
                "expiry_date": "2024-05-31",
                "reason": "Accreditation certificate expired on 2024-05-31"
            })
        elif idx == 25:
            accr_valid = "2025-01-15"
            injected.append({
                "type": "expired_accreditation",
                "rule_id": "RULE-DOC-ACCR-005",
                "severity": "Major",
                "doc_type": "Accreditation certificate",
                "expiry_date": "2025-01-15",
                "reason": "Accreditation certificate expired"
            })

        # Missing doc defect on idx 30
        missing_doc = None
        if idx == 30 and category == "New-Programme":
            missing_doc = "NOC-State Govt"
            injected.append({
                "type": "missing_document",
                "rule_id": "RULE-DOC-STATE-008",
                "severity": "Critical",
                "doc_type": "NOC-State Govt",
                "reason": "Mandatory State Government NOC document is missing from submission"
            })

        # Issuer outage simulation on idx 5 (Apex Regional University)
        simulated_issuer_status = "VERIFIED"
        if idx == 5:
            simulated_issuer_status = "SOURCE_UNAVAILABLE"
            injected.append({
                "type": "issuer_outage",
                "severity": "Minor",
                "adapter": "AffiliatingUniversityAdapter",
                "status": "SOURCE_UNAVAILABLE",
                "reason": "Affiliating University registry server timed out (deterministic simulation)"
            })
        elif idx == 12:
            simulated_issuer_status = "PENDING"
            injected.append({
                "type": "issuer_pending",
                "severity": "Minor",
                "adapter": "DigiLockerAdapter",
                "status": "PENDING",
                "reason": "DigiLocker response pending verification"
            })

        # Build Documents
        app_docs = []
        
        # 1. Fire NOC
        fire_path = os.path.join(DOCS_DIR, f"{app_id}_NOC-Fire.pdf")
        fire_payload_str = f"DOC:FIRE|ID:{inst_id}|CERT:{fire_cert_no}|VALID:{fire_valid}"
        sig = private_key.sign(fire_payload_str.encode("utf-8")).hex()
        signed_qr_payload = f"{fire_payload_str}|SIG:{sig[:32]}"

        if (is_hero or inst_id == "AICTE-PIN-007") and saved_fire_noc_bytes:
            # Write exact duplicate of Pioneer Institute's Fire NOC
            with open(fire_path, "wb") as f:
                f.write(saved_fire_noc_bytes)
        else:
            create_synthetic_pdf(
                filepath=fire_path,
                title="STATE FIRE AND EMERGENCY SERVICES",
                hindi_title="राज्य अग्निशमन एवं आपातकालीन सेवाएं",
                inst_name=inst_name,
                inst_id=inst_id,
                doc_type="NOC-Fire",
                cert_no=fire_cert_no,
                issue_date=fire_issue,
                valid_date=fire_valid,
                qr_payload=signed_qr_payload,
                extra_details=[
                    "Fire safety inspection conducted as per National Building Code (Part IV).",
                    "Hydrant system, hose reels, and smoke detectors certified operational.",
                    "Adequate egress routes and emergency evacuation stairwells verified."
                ],
                tampered_overlay=fire_tampered
            )
            # If this is Pioneer Institute, save bytes for Hero reuse
            if inst_id == "AICTE-PIN-007":
                with open(fire_path, "rb") as f:
                    saved_fire_noc_bytes = f.read()

        with open(fire_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        app_docs.append({
            "doc_id": f"DOC-{app_id}-01",
            "doc_type": "NOC-Fire",
            "filename": os.path.basename(fire_path),
            "filepath": fire_path,
            "sha256": file_hash,
            "page_count": 1,
            "declared_cert_no": fire_cert_no,
            "declared_valid_date": fire_valid
        })

        # 2. Affiliation NOC / Certificate
        affil_path = os.path.join(DOCS_DIR, f"{app_id}_NOC-Affiliating-University.pdf")
        affil_payload_str = f"DOC:AFFIL|ID:{inst_id}|CERT:{affil_cert_no}|VALID:{affil_valid}"
        affil_sig = private_key.sign(affil_payload_str.encode("utf-8")).hex()
        affil_qr = f"{affil_payload_str}|SIG:{affil_sig[:32]}"
        
        create_synthetic_pdf(
            filepath=affil_path,
            title="AFFILIATING UNIVERSITY ORDER OF ACADEMIC AFFILIATION",
            hindi_title="संबद्ध विश्वविद्यालय शैक्षणिक संबद्धता आदेश",
            inst_name=inst_name,
            inst_id=inst_id,
            doc_type="NOC-Affiliating University",
            cert_no=affil_cert_no,
            issue_date=affil_issue,
            valid_date=affil_valid if not affil_tampered else affil_tampered,
            qr_payload=affil_qr,
            extra_details=[
                "Affiliation granted under Section 14 of University Act for 2026-27.",
                "Syllabus conformance and semester examination adherence confirmed.",
                "Subject to periodic regulatory renewal."
            ],
            tampered_overlay=affil_tampered
        )
        with open(affil_path, "rb") as f:
            affil_hash = hashlib.sha256(f.read()).hexdigest()

        app_docs.append({
            "doc_id": f"DOC-{app_id}-02",
            "doc_type": "NOC-Affiliating University",
            "filename": os.path.basename(affil_path),
            "filepath": affil_path,
            "sha256": affil_hash,
            "page_count": 1,
            "declared_cert_no": affil_cert_no,
            "declared_valid_date": affil_tampered if affil_tampered else affil_valid
        })

        # 3. Accreditation Certificate
        accr_path = os.path.join(DOCS_DIR, f"{app_id}_Accreditation-Certificate.pdf")
        create_synthetic_pdf(
            filepath=accr_path,
            title="NATIONAL BOARD OF ACCREDITATION",
            hindi_title="राष्ट्रीय प्रत्यायन बोर्ड (डेमो)",
            inst_name=inst_name,
            inst_id=inst_id,
            doc_type="Accreditation certificate",
            cert_no=f"NBA-ACCR-2026-{idx+100}",
            issue_date="2021-06-01",
            valid_date=accr_valid,
            qr_payload=f"DOC:NBA|ID:{inst_id}|VALID:{accr_valid}",
            extra_details=[
                "Accredited under Tier-II outcome-based education parameters.",
                "Faculty qualifications and student outcomes assessed.",
                "Valid for undergraduate engineering programmes specified."
            ]
        )
        with open(accr_path, "rb") as f:
            accr_hash = hashlib.sha256(f.read()).hexdigest()

        app_docs.append({
            "doc_id": f"DOC-{app_id}-03",
            "doc_type": "Accreditation certificate",
            "filename": os.path.basename(accr_path),
            "filepath": accr_path,
            "sha256": accr_hash,
            "page_count": 1,
            "declared_valid_date": accr_valid
        })

        # 4. TER Payment Receipt
        ter_path = os.path.join(DOCS_DIR, f"{app_id}_TER-Receipt.pdf")
        create_synthetic_pdf(
            filepath=ter_path,
            title="AICTE CENTRAL TREASURY PAYMENT RECEIPT",
            hindi_title="एआईसीटीई केंद्रीय कोष शुल्क रसीद",
            inst_name=inst_name,
            inst_id=inst_id,
            doc_type="TER payment receipt",
            cert_no=ter_ref,
            issue_date="2026-02-10",
            valid_date="2026-12-31",
            qr_payload=f"DOC:TER|TXN:{ter_ref}|STATUS:{ter_status}",
            extra_details=[
                f"Regulatory Processing Category: {category}",
                f"Payment Gateway Status: {ter_status}",
                "Amount Paid: INR 2,50,000/-"
            ]
        )
        with open(ter_path, "rb") as f:
            ter_hash = hashlib.sha256(f.read()).hexdigest()

        app_docs.append({
            "doc_id": f"DOC-{app_id}-04",
            "doc_type": "TER payment receipt",
            "filename": os.path.basename(ter_path),
            "filepath": ter_path,
            "sha256": ter_hash,
            "page_count": 1
        })
        # 4b. Mandatory Documents for New-Programme Category
        if category == "New-Programme":
            if missing_doc != "NOC-State Govt":
                state_path = os.path.join(DOCS_DIR, f"{app_id}_NOC-State-Govt.pdf")
                create_synthetic_pdf(
                    filepath=state_path,
                    title="DIRECTORATE OF TECHNICAL EDUCATION (STATE GOVT)",
                    hindi_title="तकनीकी शिक्षा निदेशालय (राज्य सरकार)",
                    inst_name=inst_name,
                    inst_id=inst_id,
                    doc_type="NOC-State Govt",
                    cert_no=f"ST-NOC-2026-{idx+700}",
                    issue_date="2025-08-01",
                    valid_date="2027-07-31",
                    qr_payload=f"DOC:STATENOC|ID:{inst_id}|STATUS:APPROVED",
                    extra_details=[
                        "State Government concurrence granted under technical education policy.",
                        "Regional infrastructure and faculty requirements validated."
                    ]
                )
                with open(state_path, "rb") as f:
                    st_hash = hashlib.sha256(f.read()).hexdigest()
                app_docs.append({
                    "doc_id": f"DOC-{app_id}-05",
                    "doc_type": "NOC-State Govt",
                    "filename": os.path.basename(state_path),
                    "filepath": state_path,
                    "sha256": st_hash,
                    "page_count": 1
                })

            # Building plan for New-Programme
            bld_path = os.path.join(DOCS_DIR, f"{app_id}_Building-Plan.pdf")
            create_synthetic_pdf(
                filepath=bld_path,
                title="MUNICIPAL TOWN PLANNING AUTHORITY - BUILDING PLAN",
                hindi_title="नगर नियोजन प्राधिकरण - भवन मानचित्र",
                inst_name=inst_name,
                inst_id=inst_id,
                doc_type="Building plan",
                cert_no=f"BLD-APP-2026-{idx+300}",
                issue_date="2024-03-15",
                valid_date="2034-03-14",
                qr_payload=f"DOC:BLDPLAN|ID:{inst_id}|CARPET_AREA:4200_SQM",
                extra_details=[
                    "Approved institutional building master plan and structural occupancy.",
                    "Carpet area conforms to instructional specifications."
                ]
            )
            with open(bld_path, "rb") as f:
                bld_hash = hashlib.sha256(f.read()).hexdigest()
            app_docs.append({
                "doc_id": f"DOC-{app_id}-06",
                "doc_type": "Building plan",
                "filename": os.path.basename(bld_path),
                "filepath": bld_path,
                "sha256": bld_hash,
                "page_count": 1
            })

        # 5. Infrastructure Photos (Computer Lab, Library, Workshop, Classroom)
        app_photos = []
        is_blurry = (idx == 18)
        if is_blurry:
            injected.append({
                "type": "blurred_photo",
                "severity": "Minor",
                "photo_type": "Computer Lab",
                "reason": "Computer Lab photo fails clarity benchmark (Laplacian variance < 50)"
            })

        photo_types = ["Computer Lab", "Library", "Workshop", "Classroom"]
        for p_idx, p_label in enumerate(photo_types):
            p_filename = f"{app_id}_infra_{p_label.replace(' ', '_').lower()}.jpg"
            p_path = os.path.join(PHOTOS_DIR, p_filename)

            # Hero Defect 6: Two infrastructure photos are near-duplicates
            if is_hero and p_label == "Library":
                # Copy the Computer Lab image as Library with tiny modification (near duplicate)
                comp_path = os.path.join(PHOTOS_DIR, f"{app_id}_infra_computer_lab.jpg")
                img_src = Image.open(comp_path)
                # Tiniest pixel tweak so hash is near-identical
                draw_tweak = ImageDraw.Draw(img_src)
                draw_tweak.point((10, 10), fill=(254, 254, 254))
                img_src.save(p_path, format="JPEG", quality=85)
                
                injected.append({
                    "type": "near_duplicate_photos",
                    "rule_id": "RULE-INFR-PHOTO-007",
                    "severity": "Major",
                    "photo_a": f"{app_id}_infra_computer_lab.jpg",
                    "photo_b": p_filename,
                    "reason": "Infrastructure photo for Library is a near-duplicate perceptual match (pHash distance < 5) to Computer Lab photo"
                })
            else:
                generate_synthetic_photo(
                    filepath=p_path,
                    facility_type=p_label,
                    inst_name=inst_name,
                    blurry=(is_blurry and p_label == "Computer Lab"),
                    draw_seed=idx * 10 + p_idx
                )

            app_photos.append({
                "photo_id": f"PHT-{app_id}-{p_idx+1:02d}",
                "evidence_type": p_label,
                "filename": p_filename,
                "filepath": p_path
            })

        # Save to mock database structures
        mock_db["institutions"].append({
            "institution_id": inst_id,
            "name": inst_name,
            "location": location,
            "region": "Northern" if "Uttarakhand" in location or "Punjab" in location else "Central",
            "category": category
        })

        mock_db["baseline_records"].append({
            "institution_id": inst_id,
            "approved_intake": baseline_intake,
            "approved_programmes": ["Computer Science and Engineering"],
            "ter_payment_status": ter_status,
            "accreditation_status": "VALID" if "2027" in accr_valid else "EXPIRED",
            "previous_eoa_status": "APPROVED",
            "deficiency_count": 0
        })

        mock_db["applications"].append({
            "application_id": app_id,
            "institution_id": inst_id,
            "institution_name": inst_name,
            "academic_year": "2026-27",
            "category": category,
            "declared_intake": declared_intake,
            "status": "Ready for official scrutiny" if len(injected) == 0 else "Manual review / inspection recommended" if is_hero else "Rectification required",
            "created_at": "2026-03-01T10:00:00Z",
            "issuer_simulated_status": simulated_issuer_status,
            "documents": app_docs,
            "photos": app_photos
        })

        if injected:
            ground_truth["defects"][app_id] = {
                "institution_name": inst_name,
                "institution_id": inst_id,
                "category": category,
                "injected_defects": injected
            }

    # Save Ground Truth JSON
    gt_path = os.path.join(BASE_DIR, "ground_truth.json")
    with open(gt_path, "w") as f:
        json.dump(ground_truth, f, indent=2)

    # Save Seed Database JSON
    seed_path = os.path.join(OUTPUT_DIR, "seed_database.json")
    with open(seed_path, "w") as f:
        json.dump(mock_db, f, indent=2)

    print(f"[SyntheticData] Successfully created:")
    print(f" - {len(mock_db['institutions'])} Institutions")
    print(f" - {len(mock_db['applications'])} Applications")
    print(f" - Ground truth with {len(ground_truth['defects'])} defected applications saved to {gt_path}")
    print(f" - Seed database saved to {seed_path}")

if __name__ == "__main__":
    run_generation()
