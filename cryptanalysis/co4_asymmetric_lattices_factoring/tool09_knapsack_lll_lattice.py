"""
Tool 09: Merkle-Hellman Knapsack & Lattice-Reduction (LLL) Cryptanalysis Tool
Course Outcome: CO4 (Merkle Hellman Knapsack - Lattice-Reduction Attack)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import math
from typing import List, Tuple, Dict

class KnapsackLatticeAttackTool:
    """
    Implements Merkle-Hellman Knapsack encryption and its cryptanalysis via
    Lattice Basis Reduction (Lenstra-Lenstra-Lovász / LLL algorithm).
    The subset sum problem: Given public weights B = [b_1, ..., b_n] and target S = ∑ x_i * b_i (x_i in {0, 1}),
    we construct a Clos-Odlyzko lattice:
        [ 2   0  ...  0   b_1 ]
        [ 0   2  ...  0   b_2 ]
        [ ...               ]
        [ 0   0  ...  2   b_n ]
        [ 1   1  ...  1    S  ]
    Reducing this lattice with LLL yields a short vector whose coordinates reveal the secret plaintext bits x_i.
    """

    @staticmethod
    def lll_reduction(basis: List[List[float]], delta: float = 0.75) -> List[List[float]]:
        """Gram-Schmidt orthogonalization and LLL reduction in pure Python."""
        n = len(basis)
        m = len(basis[0])

        def dot(v1, v2):
            return sum(x * y for x, y in zip(v1, v2))

        def gram_schmidt(B):
            B_star = [[0.0] * m for _ in range(n)]
            mu = [[0.0] * n for _ in range(n)]
            for i in range(n):
                B_star[i] = list(B[i])
                for j in range(i):
                    mu[i][j] = dot(B[i], B_star[j]) / (dot(B_star[j], B_star[j]) + 1e-18)
                    for k in range(m):
                        B_star[i][k] -= mu[i][j] * B_star[j][k]
            return B_star, mu

        B = [list(map(float, row)) for row in basis]
        B_star, mu = gram_schmidt(B)

        k = 1
        while k < n:
            # Size reduction
            for j in range(k - 1, -1, -1):
                if abs(mu[k][j]) > 0.5:
                    q = round(mu[k][j])
                    for c in range(m):
                        B[k][c] -= q * B[j][c]
                    B_star, mu = gram_schmidt(B)

            # Lovasz condition
            norm_k = dot(B_star[k], B_star[k])
            norm_k_prev = dot(B_star[k - 1], B_star[k - 1])
            if norm_k >= (delta - mu[k][k - 1] ** 2) * norm_k_prev:
                k += 1
            else:
                B[k], B[k - 1] = B[k - 1], B[k]
                B_star, mu = gram_schmidt(B)
                k = max(k - 1, 1)

        return [[int(round(x)) for x in row] for row in B]

    def solve_knapsack(self, public_weights: List[int], ciphertext: int) -> Dict:
        """Constructs the lattice and runs LLL to extract the plaintext vector."""
        n = len(public_weights)
        # Construct (n+1) x (n+1) lattice basis
        lattice = [[0 for _ in range(n + 1)] for _ in range(n + 1)]
        for i in range(n):
            lattice[i][i] = 2
            lattice[i][n] = public_weights[i]
        for i in range(n):
            lattice[n][i] = 1
        lattice[n][n] = ciphertext

        reduced = self.lll_reduction(lattice)

        # Inspect reduced basis vectors for candidate binary solution
        recovered_bits = None
        for row in reduced:
            # Candidate solution vector coordinates should be in {+1, -1}
            # Since coordinate was 2*x_i - 1, x_i = (coord + 1) // 2
            cand1 = [(val + 1) // 2 for val in row[:n]]
            cand2 = [(-val + 1) // 2 for val in row[:n]]

            for cand in [cand1, cand2]:
                if all(b in (0, 1) for b in cand):
                    if sum(cand[i] * public_weights[i] for i in range(n)) == ciphertext:
                        recovered_bits = cand
                        break
            if recovered_bits:
                break

        return {
            "status": "SUCCESS" if recovered_bits else "FAILED",
            "public_weights": public_weights,
            "ciphertext": ciphertext,
            "recovered_plaintext_bits": recovered_bits
        }

def run_tool():
    tool = KnapsackLatticeAttackTool()
    # Superincreasing sequence masked with modular arithmetic (Merkle-Hellman)
    weights = [250, 497, 989, 1968, 3931, 7857]
    secret_bits = [1, 0, 1, 1, 0, 1]
    ct = sum(b * w for b, w in zip(secret_bits, weights))
    res = tool.solve_knapsack(weights, ct)
    res["target_bits"] = secret_bits
    return res

if __name__ == "__main__":
    print(run_tool())
