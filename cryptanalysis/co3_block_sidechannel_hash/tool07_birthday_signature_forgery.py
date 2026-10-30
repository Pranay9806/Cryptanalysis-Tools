"""
Tool 07: Digital Signature Birthday Forgery Engine
Course Outcome: CO3 (Birthday Attacks on Digital Signature)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import hashlib
import itertools
from typing import Dict, List, Tuple

class DigitalSignatureBirthdayTool:
    """
    Demonstrates the Birthday Attack on Digital Signatures.
    Scenario:
      1. Attacker drafts a benign document M_fair and a fraudulent document M_fraud.
      2. Attacker generates 2^{n/2} semantic/whitespace variants of M_fair and M_fraud.
      3. A hash collision is found: H(M_fair') == H(M_fraud').
      4. The victim signs M_fair' producing signature σ.
      5. Because H(M_fair') == H(M_fraud'), σ is mathematically valid for M_fraud' as well!
    """
    def __init__(self, truncate_bytes: int = 3):
        # Using 3 bytes (24 bits) for demonstration to ensure fast runtime
        self.truncate_bytes = truncate_bytes

    def get_truncated_hash(self, text: str) -> str:
        digest = hashlib.sha256(text.encode('utf-8')).digest()
        return digest[:self.truncate_bytes].hex()

    def generate_variants(self, template: str, options: List[List[str]]) -> List[str]:
        """Generates text variants based on interchangeable synonym/punctuation slots."""
        variants = []
        for combo in itertools.product(*options):
            variants.append(template.format(*combo))
        return variants

    def execute_forgery_search(self) -> Dict:
        # Templates with substitution slots
        fair_template = "The party {} shall transfer {} USD to account {} by end of month."
        fair_options = [
            ["Alice", "A. Smith", "Ms. Alice"],
            ["100", "100.00", "one hundred"],
            ["#1092", "No. 1092", "ID 1092"]
        ]

        fraud_template = "The party {} hereby transfers {} USD ownership to entity {} immediately."
        fraud_options = [
            ["Alice", "A. Smith", "Ms. Alice"],
            ["10,000,000", "10000000", "ten million"],
            ["#MaliciousCorp", "Eve Syndicate", "Attacker LLC"]
        ]

        # Generate large combinatorial variants with whitespace padding
        fair_map: Dict[str, str] = {}
        found_collision = None

        # Build lookup table of benign document hashes
        for base in self.generate_variants(fair_template, fair_options):
            for pad in range(500):
                text = base + (" " * pad)
                h = self.get_truncated_hash(text)
                fair_map[h] = text

        # Search fraudulent documents for matching hash
        evals = 0
        for base in self.generate_variants(fraud_template, fraud_options):
            for pad in range(1000):
                evals += 1
                fraud_text = base + (" " * pad)
                h = self.get_truncated_hash(fraud_text)
                if h in fair_map:
                    found_collision = (fair_map[h], fraud_text, h)
                    break
            if found_collision:
                break

        if found_collision:
            m_fair, m_fraud, coll_hash = found_collision
            return {
                "status": "COLLISION_FOUND",
                "collision_hash": coll_hash,
                "benign_document": m_fair.strip(),
                "fraudulent_document": m_fraud.strip(),
                "search_iterations": evals,
                "forgery_implication": "Victim's digital signature on benign contract transfers unconditionally to fraudulent contract."
            }
        return {"status": "NO_COLLISION_FOUND", "search_iterations": evals}

def run_tool():
    # 2-byte (16-bit) collision for lightning-fast demonstration
    tool = DigitalSignatureBirthdayTool(truncate_bytes=2)
    return tool.execute_forgery_search()

if __name__ == "__main__":
    print(run_tool())
