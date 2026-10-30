"""
Tool 03: Statistical Timing Side-Channel Leakage Analyzer
Course Outcome: CO3 (Sophisticated attacks on block ciphers - Side-channel attacks)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import time
import random
from typing import Dict, List

class TimingSideChannelTool:
    """
    Demonstrates side-channel vulnerability arising from non-constant-time comparisons.
    In vulnerable implementations (e.g., early-exit string comparisons), each correct byte
    in an input token adds a measurable delay, allowing an attacker to deduce the secret.
    """
    def __init__(self, secret: str, base_delay: float = 0.0005):
        self.secret = secret
        self.base_delay = base_delay

    def vulnerable_verify(self, candidate: str) -> bool:
        """Simulates variable-time early-exit byte comparison with artificial delay."""
        if len(candidate) != len(self.secret):
            return False
        for c1, c2 in zip(candidate, self.secret):
            time.sleep(self.base_delay)  # Delay per matched comparison
            if c1 != c2:
                return False
        return True

    def constant_time_verify(self, candidate: str) -> bool:
        """Constant-time comparison resistant to timing side-channels."""
        if len(candidate) != len(self.secret):
            return False
        result = 0
        for c1, c2 in zip(candidate, self.secret):
            result |= ord(c1) ^ ord(c2)
            time.sleep(self.base_delay)
        return result == 0

    def attack_character_position(self, prefix: str, charset: str = "abcdef0123456789", trials: int = 5) -> str:
        """
        Profiles timing across character candidates to discover the character with highest average response latency.
        """
        timings: Dict[str, float] = {}
        target_len = len(self.secret)

        for char in charset:
            candidate = (prefix + char).ljust(target_len, '0')
            elapsed_total = 0.0
            for _ in range(trials):
                t0 = time.perf_counter()
                self.vulnerable_verify(candidate)
                t1 = time.perf_counter()
                elapsed_total += (t1 - t0)
            timings[char] = elapsed_total / trials

        # The correct character takes the longest time because comparison proceeds to the next character
        best_char = max(timings, key=timings.get)
        return best_char

def run_tool():
    secret_key = "a7b"
    tool = TimingSideChannelTool(secret=secret_key, base_delay=0.0002)
    discovered = ""
    for _ in range(len(secret_key)):
        next_ch = tool.attack_character_position(discovered, charset="ab7c01", trials=3)
        discovered += next_ch
    return {
        "status": "SUCCESS",
        "recovered_secret": discovered,
        "is_correct": discovered == secret_key
    }

if __name__ == "__main__":
    print(run_tool())
