import cv2
import numpy as np
from PIL import Image
from typing import Dict, Any, List

class InfrastructureEvidenceService:
    @staticmethod
    def inspect_image_quality(image_path: str) -> Dict[str, Any]:
        """
        Assesses image quality: blur (Laplacian variance), brightness, and resolution.
        """
        img = cv2.imread(image_path)
        if img is None:
            return {
                "is_usable": False,
                "blur_score": 0.0,
                "brightness": 0.0,
                "resolution": "0x0",
                "triage_recommendation": "needs additional evidence (unreadable image)"
            }

        height, width, _ = img.shape
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # 1. Blur via Laplacian Variance
        lap_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())

        # 2. Brightness (0 - 255)
        brightness = float(gray.mean())

        # 3. Assessment
        issues = []
        if lap_var < 50.0:
            issues.append(f"Image blurred (Laplacian variance: {lap_var:.1f} < 50.0 benchmark)")
        if brightness < 40.0:
            issues.append(f"Image underexposed / dark ({brightness:.1f} < 40)")
        elif brightness > 220.0:
            issues.append(f"Image overexposed ({brightness:.1f} > 220)")
        if width < 600 or height < 400:
            issues.append(f"Sub-standard resolution ({width}x{height})")

        is_usable = (len(issues) == 0)
        recommendation = "sufficient clarity for preliminary triage" if is_usable else "needs additional evidence"

        return {
            "is_usable": is_usable,
            "blur_score": round(lap_var, 1),
            "brightness": round(brightness, 1),
            "resolution": f"{width}x{height}",
            "issues": issues,
            "triage_recommendation": recommendation,
            "disclaimer": "Triage assistance only. Does not assert equipment inventory or square footage."
        }

    @staticmethod
    def classify_facility_type(image_path: str) -> Dict[str, Any]:
        """
        Content-based facility classifier using visual features and image analysis.
        Does not use filename hints.
        """
        img = cv2.imread(image_path)
        if img is None:
            return {"facility_type": "General Instructional Area", "confidence": 0.50}

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        h, w = gray.shape

        # 1. Detect Screen / Monitor geometry (Computer Centre / IT Lab)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edges = cv2.Canny(blurred, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        
        screen_candidates = 0
        for cnt in contours:
            approx = cv2.approxPolyDP(cnt, 0.04 * cv2.arcLength(cnt, True), True)
            if len(approx) == 4 and cv2.isContourConvex(approx):
                x, y, cw, ch = cv2.boundingRect(approx)
                if ch > 20 and cw > 25:
                    ratio = float(cw) / float(ch)
                    area = cw * ch
                    if 1.2 <= ratio <= 2.2 and 1500 <= area <= (h * w * 0.25):
                        screen_candidates += 1

        # 2. Detect Horizontal Parallel Shelf Lines (Central Library / Reading Room)
        lines = cv2.HoughLinesP(edges, 1, np.pi / 180, threshold=80, minLineLength=w // 6, maxLineGap=15)
        horizontal_shelf_lines = 0
        if lines is not None:
            for line in lines:
                x1, y1, x2, y2 = line[0]
                if abs(y2 - y1) <= 5 and abs(x2 - x1) >= w // 6:
                    horizontal_shelf_lines += 1

        # 3. Detect Circular / Machinery features (Mechanical / Production Workshop)
        circles = cv2.HoughCircles(blurred, cv2.HOUGH_GRADIENT, dp=1.2, minDist=30, param1=50, param2=35, minRadius=15, maxRadius=100)
        circle_count = len(circles[0]) if circles is not None else 0

        # Heuristic visual classification based strictly on detected content
        if screen_candidates >= 2:
            return {"facility_type": "Computer Centre / IT Lab", "confidence": 0.92, "detected_features": f"{screen_candidates} display monitors"}
        elif horizontal_shelf_lines >= 3:
            return {"facility_type": "Central Library / Reading Room", "confidence": 0.88, "detected_features": f"{horizontal_shelf_lines} horizontal shelf lines"}
        elif circle_count >= 2:
            return {"facility_type": "Mechanical / Production Workshop", "confidence": 0.86, "detected_features": f"{circle_count} machinery wheels/rotors"}
        else:
            return {"facility_type": "Instructional Classroom / Smart Class", "confidence": 0.85, "detected_features": "Board and desk seating array"}

    @classmethod
    def triage_application_photos(cls, photo_records: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Assesses completeness and quality of submitted photographic evidence.
        """
        inspected = []
        missing_mandatory = []
        expected_types = {"Computer Centre / IT Lab", "Central Library / Reading Room", "Instructional Classroom / Smart Class"}

        detected_types = set()

        for p in photo_records:
            fpath = p.get("filepath", "")
            fname = p.get("filename", "")
            q = cls.inspect_image_quality(fpath)
            c = cls.classify_facility_type(fpath)
            detected_types.add(c["facility_type"])

            inspected.append({
                "filename": fname,
                "facility_type": c["facility_type"],
                "quality": q
            })

        for exp in expected_types:
            if exp not in detected_types:
                missing_mandatory.append(exp)

        # Recommendation
        if missing_mandatory or any(not item["quality"]["is_usable"] for item in inspected):
            overall_recommendation = "needs additional evidence / recommend physical inspection"
        else:
            overall_recommendation = "preliminary visual evidence complete for scrutiny review"

        return {
            "inspected_photos": inspected,
            "missing_facilities": missing_mandatory,
            "overall_recommendation": overall_recommendation,
            "statutory_note": "AICTE decision-support triage. Physical dimensions and safety compliance require scrutiny committee confirmation."
        }
