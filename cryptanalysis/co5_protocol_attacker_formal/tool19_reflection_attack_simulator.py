"""
Tool 19: Symmetric Challenge-Response Reflection Attack Simulator
Course Outcome: CO5 (Typical Attacks on Authentication Protocols - Reflection Attacks)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import random
from typing import Dict, Tuple

class ReflectionAttackTool:
    """
    Demonstrates a Reflection Attack on a symmetric challenge-response authentication protocol.
    Symmetric protocol:
      1. A -> B: "I am Alice"
      2. B -> A: Challenge R_B
      3. A -> B: Response Enc(K_AB, R_B)
    Attacker (Eve) exploits protocol symmetry across concurrent sessions:
      Session 1: Eve -> Bob: "I am Alice"
      Session 1: Bob -> Eve: Challenge R1
      Session 2: Eve -> Bob: "I am Alice" (concurrent connection)
      Session 2: Bob -> Eve: Challenge R2
      Session 2: Eve -> Bob: Reflects R1 as challenge in Session 2!
      Session 2: Bob -> Eve: Enc(K_AB, R1)
      Session 1: Eve -> Bob: Sends Enc(K_AB, R1) back to Session 1!
      Bob verifies response in Session 1 and authenticates Eve without Eve ever knowing K_AB.
    """
    def __init__(self, shared_key: int = 0xDEADBEEF):
        self.k_ab = shared_key

    def _encrypt(self, nonce: int) -> int:
        """Simulated symmetric encryption with shared key."""
        return (nonce ^ self.k_ab) * 31 & 0xFFFFFFFF

    def simulate_attack(self) -> Dict:
        # Step 1: Eve opens Session 1 claiming to be Alice
        session1_challenge_r1 = random.randint(100000, 999999)

        # Step 2: Eve opens Session 2 with Bob
        session2_challenge_r2 = random.randint(100000, 999999)

        # Step 3: Reflection! Eve feeds challenge R1 into Session 2
        # Bob treats Eve as the challenger in Session 2 and computes response for R1:
        session2_response_for_r1 = self._encrypt(session1_challenge_r1)

        # Step 4: Eve copies response into Session 1
        # Bob in Session 1 verifies if response matches _encrypt(session1_challenge_r1)
        expected_response = self._encrypt(session1_challenge_r1)
        session1_authenticated = (session2_response_for_r1 == expected_response)

        return {
            "status": "SUCCESS",
            "session_1_challenge_r1": session1_challenge_r1,
            "session_2_challenge_r2": session2_challenge_r2,
            "reflected_response_used": session2_response_for_r1,
            "authentication_bypassed": session1_authenticated,
            "countermeasure": "Enforce asymmetric message tagging (e.g. Hash('INITIATOR' || R) vs Hash('RESPONDER' || R)) or dual directional keys."
        }

def run_tool():
    tool = ReflectionAttackTool()
    return tool.simulate_attack()

if __name__ == "__main__":
    print(run_tool())
