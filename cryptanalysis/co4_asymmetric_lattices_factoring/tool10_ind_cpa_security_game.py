"""
Tool 10: IND-CPA Distinguisher & Semantic Security Adversary Game
Course Outcome: CO4 (The need for randomized encryption, Semantic security against CPA)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import os
import random
from typing import Dict, Tuple

class IndCpaSecurityGameTool:
    """
    Formal IND-CPA (Indistinguishability under Chosen Plaintext Attack) Security Game.
    Evaluates semantic security:
      1. Challenger chooses secret key K and random bit b in {0, 1}.
      2. Adversary submits two equal-length messages M_0, M_1.
      3. Challenger returns challenge ciphertext C = Enc(K, M_b).
      4. Adversary guesses b'. Advantage = |2 * Pr[b' == b] - 1|.
    Proves that deterministic encryption has Advantage = 1.0 (Completely Broken),
    while randomized encryption achieves Advantage ≈ 0.0 (Semantically Secure).
    """

    @staticmethod
    def deterministic_enc(key: bytes, msg: bytes) -> bytes:
        """Simulates deterministic encryption (e.g. ECB mode): same plaintext always produces same ciphertext."""
        # Simple simulated deterministic cipher using key stream XOR
        import hashlib
        keystream = hashlib.sha256(key).digest()[:len(msg)]
        return bytes(m ^ k for m, k in zip(msg, keystream))

    @staticmethod
    def randomized_enc(key: bytes, msg: bytes) -> bytes:
        """Simulates randomized encryption (e.g. CBC with random IV): prepends fresh random nonce/IV."""
        import hashlib
        iv = os.urandom(8)
        keystream = hashlib.sha256(key + iv).digest()[:len(msg)]
        ct_body = bytes(m ^ k for m, k in zip(msg, keystream))
        return iv + ct_body

    def play_cpa_game(self, scheme_type: str = "deterministic", rounds: int = 100) -> Dict:
        key = b"secret_master_k!"
        wins = 0

        m0 = b"ATTACK_AT_DAWN!!"
        m1 = b"RETREAT_AT_DUSK!"

        for _ in range(rounds):
            b = random.randint(0, 1)
            target_msg = m0 if b == 0 else m1

            if scheme_type == "deterministic":
                c_challenge = self.deterministic_enc(key, target_msg)
                # Adversary encrypts m0 using its CPA encryption oracle
                c_test0 = self.deterministic_enc(key, m0)
                # Deterministic check
                b_guess = 0 if (c_challenge == c_test0) else 1
            else:
                c_challenge = self.randomized_enc(key, target_msg)
                # Randomized check: adversary queries oracle on m0
                c_test0 = self.randomized_enc(key, m0)
                # Because ciphertext has fresh random IV, c_challenge != c_test0 even if both encrypt m0!
                # Adversary can only guess randomly
                b_guess = random.randint(0, 1)

            if b_guess == b:
                wins += 1

        win_rate = wins / rounds
        advantage = abs(2.0 * win_rate - 1.0)

        return {
            "scheme": scheme_type,
            "total_rounds": rounds,
            "adversary_win_rate": round(win_rate, 4),
            "ind_cpa_advantage": round(advantage, 4),
            "semantically_secure": advantage < 0.2,
            "conclusion": "INSECURE (Advantage = 1.0)" if scheme_type == "deterministic" else "SECURE (Advantage ≈ 0.0)"
        }

def run_tool():
    tool = IndCpaSecurityGameTool()
    res_det = tool.play_cpa_game("deterministic", 50)
    res_rand = tool.play_cpa_game("randomized", 50)
    return {
        "status": "SUCCESS",
        "deterministic_evaluation": res_det,
        "randomized_evaluation": res_rand
    }

if __name__ == "__main__":
    print(run_tool())
