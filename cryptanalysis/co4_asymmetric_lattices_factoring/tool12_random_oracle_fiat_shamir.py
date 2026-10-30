"""
Tool 12: Random Oracle Model (ROM) vs Standard Model Simulator (Fiat-Shamir Transform)
Course Outcome: CO4 (Semantic security with and without random oracle model)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import hashlib
import random
import math
from typing import Dict, Tuple

class RandomOracleFiatShamirTool:
    """
    Demonstrates the Random Oracle Model (ROM) and the Fiat-Shamir Transformation.
    An interactive zero-knowledge identification protocol (Schnorr protocol):
      1. Prover sends commitment: R = g^v mod p
      2. Verifier sends random challenge: e
      3. Prover sends response: s = (v - e * x) mod q
    In ROM, the verifier's interactive challenge is replaced by a cryptographic hash:
      e = H(R || M) mod q
    This turns an interactive proof into a non-interactive signature.
    Security proofs in ROM rely on the ability of the reduction simulator to "program" the oracle
    and extract witness x using the Rewinding Lemma (Special Soundness).
    """
    def __init__(self, p: int = 10007, q: int = 5003, g: int = 4):
        # Subgroup of prime order q = 5003 modulo prime p = 2*q + 1 = 10007
        self.p = p
        self.q = q
        self.g = g  # Generator of prime-order subgroup: g^q = 1 mod p

    def hash_oracle(self, data: bytes) -> int:
        """Simulates Random Oracle H: {0, 1}* -> Z_q."""
        digest = hashlib.sha256(data).digest()
        return int.from_bytes(digest, 'big') % self.q

    def keygen(self) -> Tuple[int, int]:
        x = random.randint(2, self.q - 1)
        y = pow(self.g, x, self.p)
        return x, y

    def sign_fiat_shamir(self, x: int, msg: bytes) -> Tuple[int, int]:
        """Prover signs message non-interactively using ROM challenge e = H(R || M)."""
        v = random.randint(2, self.q - 1)
        R = pow(self.g, v, self.p)
        e = self.hash_oracle(f"{R}".encode() + msg)
        s = (v - e * x) % self.q
        return R, s

    def verify_fiat_shamir(self, y: int, msg: bytes, signature: Tuple[int, int]) -> bool:
        """Verifier checks: R == g^s * y^e mod p."""
        R, s = signature
        e = self.hash_oracle(f"{R}".encode() + msg)
        check = (pow(self.g, s, self.p) * pow(y, e, self.p)) % self.p
        return check == R

    def simulate_rom_honest_verifier_proof(self) -> Dict:
        """
        Simulates the ROM Special Soundness property (Extracting the private key x via rewinding).
        If an adversary can answer two distinct challenges e1, e2 for the same commitment R:
            s1 = (v - e1 * x) mod q
            s2 = (v - e2 * x) mod q
            => (s1 - s2) = (e2 - e1) * x mod q
            => x = (s1 - s2) * (e2 - e1)^{-1} mod q
        Since q is prime, (e2 - e1) is guaranteed to be invertible!
        """
        x, y = self.keygen()
        v = random.randint(2, self.q - 1)
        R = pow(self.g, v, self.p)

        # Two distinct simulated challenges in Z_q
        e1 = random.randint(1, self.q // 2)
        e2 = random.randint(self.q // 2 + 1, self.q - 1)

        s1 = (v - e1 * x) % self.q
        s2 = (v - e2 * x) % self.q

        delta_s = (s1 - s2) % self.q
        delta_e = (e2 - e1) % self.q
        extracted_x = (delta_s * pow(delta_e, -1, self.q)) % self.q

        return {
            "prover_secret_x": x,
            "extracted_secret_x": extracted_x,
            "extraction_successful": (extracted_x == x),
            "rom_security_basis": "Knowledge extractor algorithm provably recovers secret if adversary forges multiple branches in ROM."
        }

def run_tool():
    tool = RandomOracleFiatShamirTool()
    x, y = tool.keygen()
    msg = b"Transaction: Transfer 50 coins to Bob"
    sig = tool.sign_fiat_shamir(x, msg)
    is_valid = tool.verify_fiat_shamir(y, msg, sig)
    extractor_sim = tool.simulate_rom_honest_verifier_proof()

    return {
        "status": "SUCCESS",
        "signature_valid": is_valid,
        "signature_components": {"R": sig[0], "s": sig[1]},
        "rom_extractor_simulation": extractor_sim
    }

if __name__ == "__main__":
    print(run_tool())
