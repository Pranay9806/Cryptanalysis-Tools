"""
Tool 11: IND-CCA2 Security Evaluator: Malleable ElGamal vs. Cramer-Shoup
Course Outcome: CO4 (Chosen ciphertext secure ElGamal scheme)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import hashlib
import random
from typing import Dict, Tuple, Optional

class IndCca2SecurityTool:
    """
    Evaluates chosen-ciphertext attack (IND-CCA2) vulnerability in ElGamal and demonstrates
    the Cramer-Shoup extension for non-malleability and CCA2 security.
    Standard ElGamal is multiplicatively malleable:
        C = (g^r, m * h^r)  =>  C' = (g^r, 2 * m * h^r)
    Decryption of C' yields 2 * m, allowing complete recovery of m from a decryption oracle.
    Cramer-Shoup prevents this by adding a non-malleable verification tag v = c^r * d^{r * H(u1, u2, e)}.
    """
    def __init__(self, p: int = 10007, g: int = 5):
        self.p = p
        self.g = g

    # Standard ElGamal
    def elgamal_keygen(self):
        x = random.randint(2, self.p - 2)
        h = pow(self.g, x, self.p)
        return {"pk": (self.p, self.g, h), "sk": x}

    def elgamal_encrypt(self, pk, m: int) -> Tuple[int, int]:
        p, g, h = pk
        r = random.randint(2, p - 2)
        c1 = pow(g, r, p)
        c2 = (m * pow(h, r, p)) % p
        return (c1, c2)

    def elgamal_decrypt(self, sk: int, ct: Tuple[int, int]) -> int:
        c1, c2 = ct
        s = pow(c1, sk, self.p)
        s_inv = pow(s, -1, self.p)
        return (c2 * s_inv) % self.p

    def simulate_elgamal_cca2_attack(self, target_plaintext: int = 42) -> Dict:
        """Adversary doubles ciphertext and queries decryption oracle to recover secret message."""
        keys = self.elgamal_keygen()
        pk, sk = keys["pk"], keys["sk"]

        # Legitimate encryption of secret message
        c1, c2 = self.elgamal_encrypt(pk, target_plaintext)

        # CCA2 Adversary multiplies c2 by 2 mod p without knowing target_plaintext
        c2_malleated = (c2 * 2) % self.p
        c_malleated = (c1, c2_malleated)

        # Oracle decrypts modified ciphertext (allowed since c_malleated != (c1, c2))
        m_doubled = self.elgamal_decrypt(sk, c_malleated)

        # Adversary computes m = m_doubled / 2 mod p
        m_recovered = (m_doubled * pow(2, -1, self.p)) % self.p

        return {
            "target_plaintext": target_plaintext,
            "original_ciphertext": (c1, c2),
            "malleated_ciphertext": c_malleated,
            "oracle_decrypted_doubled": m_doubled,
            "recovered_plaintext": m_recovered,
            "cca2_exploit_successful": (m_recovered == target_plaintext)
        }

    # Cramer-Shoup CCA2 Resistant Scheme
    def cramer_shoup_verify_decrypt(self, sk_cs, ct_cs: Tuple[int, int, int, int]) -> Optional[int]:
        """Rejects modified ciphertexts, defeating CCA2."""
        u1, u2, e, v = ct_cs
        x1, x2, y1, y2, z = sk_cs
        # Hash commitment
        h_val = int(hashlib.sha256(f"{u1},{u2},{e}".encode()).hexdigest(), 16) % self.p
        # Verify tag v == u1^{x1 + y1 * h} * u2^{x2 + y2 * h}
        v_check = (pow(u1, x1 + y1 * h_val, self.p) * pow(u2, x2 + y2 * h_val, self.p)) % self.p
        if v != v_check:
            return None  # REJECT invalid ciphertext
        # Decrypt message m = e / u1^z
        m = (e * pow(pow(u1, z, self.p), -1, self.p)) % self.p
        return m

def run_tool():
    tool = IndCca2SecurityTool()
    res = tool.simulate_elgamal_cca2_attack(target_plaintext=77)
    return {
        "status": "SUCCESS",
        "elgamal_cca2_attack_result": res,
        "countermeasure": "Cramer-Shoup adds hash-based validity verification tag to reject manipulated ciphertexts."
    }

if __name__ == "__main__":
    print(run_tool())
