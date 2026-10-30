"""
Tool 05: Quantum Exhaustive Key Search Simulator (Grover's Algorithm)
Course Outcome: CO3 (Sophisticated attacks on block ciphers - Quantum exhaustive search attacks)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import math
from typing import List, Dict

class GroverQuantumSearchTool:
    """
    Simulates Grover's Quantum Search Algorithm for key exhaustion.
    Classical key search requires O(N) operations (e.g. 2^128 operations for AES-128).
    Grover's quantum algorithm reduces exhaustive search complexity to O(sqrt(N)) (e.g. 2^64 operations),
    effectively halving the symmetric security bit length.
    """
    def __init__(self, key_bits: int, target_key: int):
        self.n_bits = key_bits
        self.N = 1 << key_bits
        self.target = target_key
        # Optimal number of Grover iterations: R ≈ (pi / 4) * sqrt(N)
        self.optimal_iterations = max(1, int(round((math.pi / 4.0) * math.sqrt(self.N))))

    def run_simulation(self) -> Dict:
        """Simulates state vector evolution through superposition, oracle phase flip, and diffusion."""
        # 1. Initialize uniform superposition: |s> = 1/sqrt(N) ∑ |x>
        state = [1.0 / math.sqrt(self.N)] * self.N

        for step in range(self.optimal_iterations):
            # 2. Phase Inversion Oracle: |x> -> -|x> if x == target else |x>
            state[self.target] = -state[self.target]

            # 3. Grover Diffusion Operator (Inversion about average)
            # D = 2|s><s| - I  =>  x_new = 2 * mean(x) - x_old
            avg_amplitude = sum(state) / self.N
            state = [2.0 * avg_amplitude - amp for amp in state]

        # Compute probability distribution
        probabilities = [amp ** 2 for amp in state]
        target_prob = probabilities[self.target]
        measured_key = max(range(self.N), key=lambda i: probabilities[i])

        return {
            "key_space_size": self.N,
            "optimal_iterations": self.optimal_iterations,
            "classical_expected_queries": self.N // 2,
            "quantum_speedup_factor": round((self.N // 2) / self.optimal_iterations, 2),
            "target_key": hex(self.target),
            "measured_key": hex(measured_key),
            "target_success_probability": round(target_prob, 4)
        }

def run_tool():
    # 6-bit key search (N=64 keys)
    tool = GroverQuantumSearchTool(key_bits=6, target_key=0x2A)
    return tool.run_simulation()

if __name__ == "__main__":
    print(run_tool())
