"""
Tool 06: Hash Birthday Collision Engine & Complexity Verifier
Course Outcome: CO3 (Birthday Attacks on Hash Functions)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import hashlib
import math
from typing import Dict, Tuple

class HashBirthdayAttackTool:
    """
    Demonstrates the Birthday Attack on cryptographic hash functions.
    By the birthday paradox, finding a collision H(m1) == H(m2) in an n-bit hash space
    requires only ~1.177 * sqrt(2^n) ≈ 2^(n/2) hash evaluations, rather than 2^n.
    Implements Floyd's cycle-finding algorithm (tortoise and hare) with O(1) memory.
    """
    def __init__(self, truncate_bits: int = 24):
        self.truncate_bits = truncate_bits
        self.mask = (1 << truncate_bits) - 1
        self.theoretical_bound = int(round(1.177 * math.sqrt(1 << truncate_bits)))

    def step_function(self, x: int) -> int:
        """Compression function mapping integer to truncated SHA-256 digest."""
        data = x.to_bytes((x.bit_length() + 7) // 8 or 1, byteorder='big')
        digest = hashlib.sha256(data).digest()
        # Truncate to the lowest self.truncate_bits
        val = int.from_bytes(digest[:4], byteorder='big')
        return val & self.mask

    def find_collision(self, seed: int = 42) -> Dict:
        """Executes Floyd's cycle-finding algorithm to find two distinct inputs yielding identical digest."""
        tortoise = self.step_function(seed)
        hare = self.step_function(self.step_function(seed))
        eval_count = 3

        # Phase 1: Detect cycle
        while tortoise != hare:
            tortoise = self.step_function(tortoise)
            hare = self.step_function(self.step_function(hare))
            eval_count += 3

        # Phase 2: Find collision entry point
        # Move one pointer to start
        mu = 0
        tortoise = seed
        prev_tortoise = tortoise
        prev_hare = hare

        while tortoise != hare:
            prev_tortoise = tortoise
            prev_hare = hare
            tortoise = self.step_function(tortoise)
            hare = self.step_function(hare)
            mu += 1
            eval_count += 2

        # The collision occurred between prev_tortoise and prev_hare
        hash1 = self.step_function(prev_tortoise)
        hash2 = self.step_function(prev_hare)

        return {
            "truncated_bits": self.truncate_bits,
            "theoretical_expected_steps": self.theoretical_bound,
            "actual_evaluations": eval_count,
            "collision_found": (prev_tortoise != prev_hare) and (hash1 == hash2),
            "input_1": hex(prev_tortoise),
            "input_2": hex(prev_hare),
            "colliding_digest": hex(hash1)
        }

def run_tool():
    # 20-bit collision search (~1200 evaluations)
    tool = HashBirthdayAttackTool(truncate_bits=20)
    return tool.find_collision(seed=12345)

if __name__ == "__main__":
    print(run_tool())
