"""
Tool 02: S-Box Linear Approximation Table (LAT) Calculator & Bias Miner
Course Outcome: CO3 (Sophisticated attacks on block ciphers - Linear Cryptanalysis on DES)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

from typing import List, Dict

class LinearCryptanalysisTool:
    """
    Computes the Linear Approximation Table (LAT) for an S-Box based on Matsui's algorithm:
        LAT[α][β] = #{ X : (α · X) == (β · S(X)) } - 2^{n-1}
    where α is the input bit mask, β is the output bit mask, and (·) is the bitwise inner product mod 2.
    """
    def __init__(self, sbox: List[int], input_bits: int = 4, output_bits: int = 4):
        self.sbox = sbox
        self.in_bits = input_bits
        self.out_bits = output_bits
        self.num_inputs = 1 << input_bits
        self.num_outputs = 1 << output_bits

    @staticmethod
    def parity(val: int) -> int:
        """Computes the parity (mod 2 sum of bits)."""
        return bin(val).count('1') & 1

    def compute_lat(self) -> List[List[int]]:
        """Generates the full Linear Approximation Table containing Matsui biases."""
        half_n = self.num_inputs // 2
        lat = [[0 for _ in range(self.num_outputs)] for _ in range(self.num_inputs)]

        for alpha in range(self.num_inputs):
            for beta in range(self.num_outputs):
                matches = 0
                for x in range(self.num_inputs):
                    y = self.sbox[x]
                    in_parity = self.parity(alpha & x)
                    out_parity = self.parity(beta & y)
                    if in_parity == out_parity:
                        matches += 1
                lat[alpha][beta] = matches - half_n
        return lat

    def find_highest_biases(self, lat: List[List[int]], top_k: int = 5) -> List[Dict]:
        """Extracts the linear approximations with the maximum absolute bias |ε|."""
        records = []
        for a in range(self.num_inputs):
            for b in range(self.num_outputs):
                if a == 0 and b == 0:
                    continue
                bias = lat[a][b] / self.num_inputs
                records.append({
                    "alpha_mask": hex(a),
                    "beta_mask": hex(b),
                    "count_diff": lat[a][b],
                    "bias": round(bias, 4),
                    "abs_bias": abs(bias)
                })
        records.sort(key=lambda r: r["abs_bias"], reverse=True)
        return records[:top_k]

def run_tool():
    sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
    tool = LinearCryptanalysisTool(sbox, 4, 4)
    lat = tool.compute_lat()
    top_biases = tool.find_highest_biases(lat, 3)
    return {"status": "SUCCESS", "top_linear_approximations": top_biases}

if __name__ == "__main__":
    print(run_tool())
