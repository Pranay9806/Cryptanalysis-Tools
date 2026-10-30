"""
Tool 13: ElGamal Signature Nonce-Reuse & Private Key Recovery Engine
Course Outcome: CO4 (Strong and Provable Security for ElGamal-family Signatures)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import math
from typing import Dict, Tuple

class ElGamalSignatureNonceReuseTool:
    """
    Demonstrates private key recovery on ElGamal-family digital signatures under ephemeral nonce reuse.
    In ElGamal signature:
        r = g^k mod p
        s = k^{-1} * (H(m) - x * r) mod (p - 1)
    If the signer reuses the same nonce k for two distinct messages m1 and m2:
        s1 - s2 = k^{-1} * (H(m1) - H(m2)) mod (p - 1)
        => k = (H(m1) - H(m2)) * (s1 - s2)^{-1} mod (p - 1)
    Once k is known, the private key x is recovered via:
        x = (H(m1) - k * s1) * r^{-1} mod (p - 1)
    """
    def __init__(self, p: int = 10007, g: int = 5):
        self.p = p
        self.q = p - 1
        self.g = g

    def sign(self, x: int, k: int, m_hash: int) -> Tuple[int, int]:
        """Generates ElGamal signature (r, s) with specific ephemeral nonce k."""
        r = pow(self.g, k, self.p)
        k_inv = pow(k, -1, self.q)
        s = (k_inv * (m_hash - x * r)) % self.q
        return r, s

    def recover_private_key(self, m1_hash: int, sig1: Tuple[int, int],
                                  m2_hash: int, sig2: Tuple[int, int]) -> Dict:
        """Extracts ephemeral nonce k and master private key x from two nonce-reusing signatures."""
        r1, s1 = sig1
        r2, s2 = sig2

        if r1 != r2:
            return {"status": "FAILED", "reason": "Signatures do not share the same nonce r."}

        r = r1
        # Calculate k: k * (s1 - s2) = (m1 - m2) mod q
        delta_s = (s1 - s2) % self.q
        delta_m = (m1_hash - m2_hash) % self.q

        gcd_val = math.gcd(delta_s, self.q)
        if gcd_val != 1:
            # Handle non-coprime modulus reduction
            delta_s_reduced = delta_s // gcd_val
            delta_m_reduced = delta_m // gcd_val
            q_reduced = self.q // gcd_val
            k_base = (delta_m_reduced * pow(delta_s_reduced, -1, q_reduced)) % q_reduced

            candidate_ks = [k_base + i * q_reduced for i in range(gcd_val)]
            recovered_k = None
            for cand in candidate_ks:
                if pow(self.g, cand, self.p) == r:
                    recovered_k = cand
                    break
        else:
            recovered_k = (delta_m * pow(delta_s, -1, self.q)) % self.q

        if not recovered_k:
            return {"status": "FAILED", "reason": "Failed to invert delta_s."}

        # Calculate private key x: x * r = (m1 - k * s1) mod q
        numerator = (m1_hash - recovered_k * s1) % self.q
        r_gcd = math.gcd(r, self.q)
        if r_gcd == 1:
            recovered_x = (numerator * pow(r, -1, self.q)) % self.q
        else:
            num_red = numerator // r_gcd
            r_red = r // r_gcd
            q_red = self.q // r_gcd
            x_base = (num_red * pow(r_red, -1, q_red)) % q_red
            recovered_x = x_base

        return {
            "status": "SUCCESS",
            "recovered_nonce_k": recovered_k,
            "recovered_private_key_x": recovered_x
        }

def run_tool():
    tool = ElGamalSignatureNonceReuseTool()
    secret_x = 4321
    fixed_k = 789  # Reused ephemeral nonce

    msg1_hash = 1111
    msg2_hash = 2222

    sig1 = tool.sign(secret_x, fixed_k, msg1_hash)
    sig2 = tool.sign(secret_x, fixed_k, msg2_hash)

    attack_res = tool.recover_private_key(msg1_hash, sig1, msg2_hash, sig2)
    attack_res["actual_private_key"] = secret_x
    attack_res["verified"] = (attack_res.get("recovered_private_key_x") == secret_x)
    return attack_res

if __name__ == "__main__":
    print(run_tool())
