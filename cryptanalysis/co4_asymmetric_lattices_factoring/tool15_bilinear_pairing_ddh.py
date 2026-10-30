"""
Tool 15: Bilinear Pairing Decisional Diffie-Hellman (DDH) Solver & Tri-Partite Engine
Course Outcome: CO4 (Pairing based cryptography - Bilinear pairing)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

from typing import Dict, Tuple

class BilinearPairingTool:
    """
    Demonstrates Bilinear Pairings and the efficient resolution of Decisional Diffie-Hellman (DDH).
    A pairing e: G1 x G1 -> GT satisfies:
      e(g^a, g^b) = e(g, g)^{ab}
    While DDH (deciding if g^c == g^{ab}) is assumed hard in standard groups,
    a bilinear pairing solves DDH in polynomial time:
      Test if e(g^a, g^b) == e(g, g^c).
    Also simulates Joux's 1-round 3-party key agreement: K = e(g, g)^{abc}.
    """
    def __init__(self, order_q: int = 1009):
        self.q = order_q

    def pairing_map(self, a_exp: int, b_exp: int) -> int:
        """
        Simulates the canonical bilinear pairing evaluation:
        e(g^a, g^b) = (g_T)^{a * b mod q}
        """
        # Exponent in target group G_T
        return (a_exp * b_exp) % self.q

    def solve_ddh(self, ga_exp: int, gb_exp: int, candidate_gc_exp: int) -> bool:
        """
        Solves the Decisional Diffie-Hellman problem:
        Given g^a, g^b, g^c, decides if c == a * b (mod q).
        """
        lhs = self.pairing_map(ga_exp, gb_exp)     # e(g^a, g^b) = e(g, g)^{ab}
        rhs = self.pairing_map(1, candidate_gc_exp)  # e(g^1, g^c) = e(g, g)^c
        return lhs == rhs

    def joux_tripartite_key_exchange(self, a: int, b: int, c: int) -> Dict:
        """
        Simulates Joux's 1-round tri-partite Diffie-Hellman key agreement:
        Alice broadcasts g^a, Bob broadcasts g^b, Charlie broadcasts g^c.
        Alice computes:   K_A = e(g^b, g^c)^a = e(g, g)^{abc}
        Bob computes:     K_B = e(g^a, g^c)^b = e(g, g)^{abc}
        Charlie computes: K_C = e(g^a, g^b)^c = e(g, g)^{abc}
        """
        k_alice = (self.pairing_map(b, c) * a) % self.q
        k_bob = (self.pairing_map(a, c) * b) % self.q
        k_charlie = (self.pairing_map(a, b) * c) % self.q

        shared_key = (a * b * c) % self.q

        return {
            "alice_shared_key": k_alice,
            "bob_shared_key": k_bob,
            "charlie_shared_key": k_charlie,
            "keys_match": (k_alice == k_bob == k_charlie == shared_key)
        }

def run_tool():
    tool = BilinearPairingTool(order_q=1009)
    a, b = 27, 43
    valid_c = (a * b) % 1009
    bogus_c = 999

    ddh_valid = tool.solve_ddh(a, b, valid_c)
    ddh_bogus = tool.solve_ddh(a, b, bogus_c)
    joux = tool.joux_tripartite_key_exchange(a, b, 15)

    return {
        "status": "SUCCESS",
        "ddh_valid_tuple_detected": ddh_valid,
        "ddh_bogus_tuple_rejected": not ddh_bogus,
        "joux_tripartite_agreement": joux,
        "cryptanalytic_significance": "Pairings break the DDH assumption, rendering DDH-based cryptosystems insecure in pairing-friendly groups."
    }

if __name__ == "__main__":
    print(run_tool())
