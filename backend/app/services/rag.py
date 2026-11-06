import os
import re
from typing import Dict, Any, List, Optional

KB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "knowledge_base", "synthetic_handbook_clauses.md")

class SyntheticHandbookRAGService:
    _clauses = None

    @classmethod
    def load_clauses(cls) -> List[Dict[str, Any]]:
        if cls._clauses is not None:
            return cls._clauses

        cls._clauses = []
        if not os.path.exists(KB_PATH):
            return cls._clauses

        with open(KB_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        # Split by Clause sections
        raw_sections = content.split("### Clause ID:")
        for sec in raw_sections[1:]:
            lines = sec.strip().split("\n")
            clause_id = lines[0].strip()
            
            category = ""
            acad_year = "2026-27"
            version = "1.0.0"
            summary = ""
            rule_text = ""

            for line in lines[1:]:
                line = line.strip()
                if line.startswith("- **Category**:"):
                    category = line.split(":", 1)[1].strip()
                elif line.startswith("- **Academic Year**:"):
                    acad_year = line.split(":", 1)[1].strip()
                elif line.startswith("- **Version**:"):
                    version = line.split(":", 1)[1].strip()
                elif line.startswith("- **Summary**:"):
                    summary = line.split(":", 1)[1].strip()
                elif line.startswith("- **Rule Text**:"):
                    rule_text = line.split(":", 1)[1].strip()

            cls._clauses.append({
                "clause_id": clause_id,
                "category": category,
                "academic_year": acad_year,
                "version": version,
                "summary": summary,
                "rule_text": rule_text,
                "search_blob": f"{clause_id} {category} {summary} {rule_text}".lower()
            })

        return cls._clauses

    @classmethod
    def query(cls, prompt: str, category_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Hybrid retrieval over synthetic clauses.
        Returns structured explanation with clause citations, or explicit abstain.
        """
        clauses = cls.load_clauses()
        if not prompt or not clauses:
            return {
                "found": False,
                "answer": "Not found in knowledge base",
                "citations": []
            }

        prompt_lower = prompt.lower()
        tokens = set(re.findall(r'\b[a-z0-9_\-\.]{3,}\b', prompt_lower))

        scored = []
        for c in clauses:
            score = 0
            # Exact Clause ID match
            if c["clause_id"].lower() in prompt_lower:
                score += 50
            # Token overlap
            blob_tokens = set(re.findall(r'\b[a-z0-9_\-\.]{3,}\b', c["search_blob"]))
            overlap = tokens.intersection(blob_tokens)
            score += len(overlap) * 5

            # Keywords boost
            if "intake" in tokens and "intake" in c["search_blob"]:
                score += 15
            if "fire" in tokens and "fire" in c["search_blob"]:
                score += 15
            if "affil" in prompt_lower and "affil" in c["search_blob"]:
                score += 15
            if "ter" in tokens and "ter" in c["search_blob"]:
                score += 15
            if "accredit" in tokens and "accredit" in c["search_blob"]:
                score += 15
            if "reuse" in tokens and "reuse" in c["search_blob"]:
                score += 15

            if score > 10:
                scored.append((score, c))

        scored.sort(key=lambda x: x[0], reverse=True)

        if not scored:
            return {
                "found": False,
                "answer": "Not found in knowledge base",
                "citations": []
            }

        best_score, top_clause = scored[0]
        citations = [{
            "clause_id": top_clause["clause_id"],
            "academic_year": top_clause["academic_year"],
            "version": top_clause["version"],
            "category": top_clause["category"],
            "summary": top_clause["summary"]
        }]

        # Construct deterministic structured response
        explanation = (
            f"According to synthetic regulatory handbook provision {top_clause['clause_id']} "
            f"({top_clause['category']}): {top_clause['summary']}. "
            f"\n\nApplicable Norm: \"{top_clause['rule_text']}\""
        )

        return {
            "found": True,
            "answer": explanation,
            "citations": citations,
            "disclaimer": "All citations reference SYNTHETIC-DEMO handbook clauses for SIH 2026."
        }
