"""
Tool 17: Needham-Schroeder Symmetric Replay Attack Demonstrator & Denning-Sacco Fix
Course Outcome: CO5 (Typical Attacks on Authentication Protocols - Replay Attacks)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import time
from typing import Dict, Tuple

class NeedhamSchroederReplayTool:
    """
    Demonstrates the classic Denning-Sacco replay vulnerability in the Needham-Schroeder Symmetric Protocol.
    Vulnerability:
      In Message 3, Alice forwards the ticket to Bob: {K_{AB}, A}_{K_B}.
      Because this ticket contains neither a timestamp nor Bob's nonce, an attacker (Eve) who
      learns an old session key K_{AB} can replay the old ticket {K_{AB}, A}_{K_B} to Bob.
      Bob generates a fresh challenge {N_B}_{K_{AB}}, which Eve easily answers since she knows K_{AB}.
      Bob falsely authenticates Eve as Alice.
    Countermeasure (Denning-Sacco):
      Add a trusted timestamp T inside Bob's ticket: {K_{AB}, A, T}_{K_B}.
    """
    def __init__(self, key_b: int = 0x99AABBCC):
        self.kb = key_b  # Bob's long term key

    def create_vulnerable_ticket(self, kab: int, alice_id: str = "Alice") -> Dict:
        """Simulates KDC generating vulnerable ticket for Bob without timestamp."""
        # Simulated encryption under Kb
        return {"kab": kab, "principal": alice_id, "signature": (kab ^ self.kb)}

    def bob_verify_vulnerable_ticket(self, ticket: Dict, nb_response: int, expected_nb: int) -> bool:
        """Bob verifies ticket and response in vulnerable Needham-Schroeder."""
        # Bob validates ticket integrity
        if (ticket["kab"] ^ self.kb) != ticket["signature"]:
            return False
        # Bob verifies challenge response N_B - 1
        return nb_response == (expected_nb - 1)

    def create_denning_sacco_secure_ticket(self, kab: int, alice_id: str, timestamp: float) -> Dict:
        """Denning-Sacco fix: Embeds timestamp inside Bob's ticket."""
        t_int = int(timestamp)
        return {"kab": kab, "principal": alice_id, "timestamp": t_int, "signature": (kab ^ t_int ^ self.kb)}

    def bob_verify_secure_ticket(self, ticket: Dict, current_time: float, max_skew_sec: float = 60.0) -> Tuple[bool, str]:
        """Bob verifies timestamp freshness."""
        if (ticket["kab"] ^ ticket["timestamp"] ^ self.kb) != ticket["signature"]:
            return False, "INVALID_SIGNATURE"
        if abs(current_time - ticket["timestamp"]) > max_skew_sec:
            return False, "TICKET_EXPIRED_REPLAY_DETECTED"
        return True, "AUTHENTICATION_SUCCESS"

def run_tool():
    tool = NeedhamSchroederReplayTool()

    # 1. Past session key leaked to Eve
    old_kab = 0x11223344
    captured_ticket = tool.create_vulnerable_ticket(kab=old_kab, alice_id="Alice")

    # 2. Replay attack: Eve replays old captured ticket to Bob
    bobs_fresh_nonce = 778899
    # Eve decrypts Bob's challenge using compromised old_kab and replies with N_B - 1
    eves_response = bobs_fresh_nonce - 1
    replay_success = tool.bob_verify_vulnerable_ticket(captured_ticket, eves_response, bobs_fresh_nonce)

    # 3. Secure Protocol (Denning-Sacco): Eve replays an expired timestamped ticket
    past_timestamp = time.time() - 3600  # 1 hour ago
    secure_expired_ticket = tool.create_denning_sacco_secure_ticket(old_kab, "Alice", past_timestamp)
    is_valid, reason = tool.bob_verify_secure_ticket(secure_expired_ticket, current_time=time.time())

    return {
        "status": "SUCCESS",
        "vulnerable_protocol_replay_successful": replay_success,
        "secure_denning_sacco_replay_prevented": not is_valid,
        "security_verdict": reason
    }

if __name__ == "__main__":
    print(run_tool())
