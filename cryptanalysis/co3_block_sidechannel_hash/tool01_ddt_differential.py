"""
Tool 01: S-Box Difference Distribution Table (DDT) Generator & Differential Analyzer
Course Outcome: CO3 (Sophisticated attacks on block ciphers - Differential Cryptanalysis on DES)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

from typing import List, Tuple, Dict

class DifferentialCryptanalysisTool:
    """
    Computes and analyzes the Difference Distribution Table (DDT) of an S-Box.
    In differential cryptanalysis (Biham & Shamir), an attacker analyzes how input XOR differences
    propagate to output XOR differences:
        DDT[ΔX][ΔY] = #{ X : S(X) ^ S(X ^ ΔX) == ΔY }
    """
    def __init__(self, sbox: List[int], input_bits: int = 4, output_bits: int = 4):
        self.sbox = sbox
        self.in_bits = input_bits
        self.out_bits = output_bits
        self.num_inputs = 1 << input_bits
        self.num_outputs = 1 << output_bits

    def compute_ddt(self) -> List[List[int]]:
        """Constructs the full difference distribution table."""
        ddt = [[0 for _ in range(self.num_outputs)] for _ in range(self.num_inputs)]
        for delta_x in range(self.num_inputs):
            for x in range(self.num_inputs):
                x_prime = x ^ delta_x
                y = self.sbox[x]
                y_prime = self.sbox[x_prime]
                delta_y = y ^ y_prime
                ddt[delta_x][delta_y] += 1
        return ddt

    def find_max_differentials(self, ddt: List[List[int]], top_k: int = 5) -> List[Dict]:
        """Identifies non-trivial differentials with the highest propagation probability."""
        differentials = []
        for dx in range(1, self.num_inputs):  # Skip ΔX = 0
            for dy in range(self.num_outputs):
                count = ddt[dx][dy]
                if count > 0:
                    prob = count / self.num_inputs
                    differentials.append({
                        "delta_x": hex(dx),
                        "delta_y": hex(dy),
                        "count": count,
                        "probability": round(prob, 4)
                    })
        differentials.sort(key=lambda d: d["count"], reverse=True)
        return differentials[:top_k]

# Sample execution helper
def run_tool():
    # Example 4-bit S-Box (e.g. Present S-Box)
    sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
    tool = DifferentialCryptanalysisTool(sbox, 4, 4)
    ddt = tool.compute_ddt()
    top = tool.find_max_differentials(ddt, 3)
    return {"status": "SUCCESS", "top_differentials": top}

if __name__ == "__main__":
    res = run_tool()
    print("Tool 01 Output:", res)
