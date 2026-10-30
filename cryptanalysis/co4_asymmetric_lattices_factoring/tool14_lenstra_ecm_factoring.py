"""
Tool 14: Lenstra's Elliptic Curve Method (ECM) Factoring Engine
Course Outcome: CO4 (The elliptic curve factoring method)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import math
import random
from typing import Optional, Tuple, Dict

class LenstraECMFactoringTool:
    """
    Implements Lenstra's Elliptic Curve Factoring Method (ECM).
    ECM is a sub-exponential factoring algorithm whose runtime depends on the smallest prime factor p of N.
    It selects random elliptic curves E: y^2 = x^3 + a*x + b mod N and a point P.
    By computing k*P using smooth scalar k = ∏ p_i^{e_i}, if the order of E mod p divides k,
    the addition step requires inverting a multiple of p mod N.
    Computing gcd(denominator, N) yields the non-trivial factor p.
    """

    @staticmethod
    def _inv_mod(n: int, m: int) -> Tuple[int, int]:
        """Returns (gcd, inverse mod m). If gcd > 1, inversion failed and gcd is a factor!"""
        g = math.gcd(n, m)
        if g != 1:
            return g, 0
        return 1, pow(n, -1, m)

    def _point_add(self, P: Tuple[int, int], Q: Tuple[int, int], a: int, N: int) -> Tuple[Optional[Tuple[int, int]], Optional[int]]:
        """Adds points P and Q on y^2 = x^3 + ax + b mod N."""
        if P is None: return Q, None
        if Q is None: return P, None

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            if (y1 + y2) % N == 0:
                return None, None
            # Point doubling: lambda = (3*x1^2 + a) / (2*y1) mod N
            num = (3 * x1 * x1 + a) % N
            den = (2 * y1) % N
        else:
            # Point addition: lambda = (y2 - y1) / (x2 - x1) mod N
            num = (y2 - y1) % N
            den = (x2 - x1) % N

        g, den_inv = self._inv_mod(den, N)
        if g > 1 and g < N:
            return None, g  # Non-trivial factor found!
        if g == N:
            return None, None

        lam = (num * den_inv) % N
        x3 = (lam * lam - x1 - x2) % N
        y3 = (lam * (x1 - x3) - y1) % N
        return (x3, y3), None

    def _scalar_multiply(self, k: int, P: Tuple[int, int], a: int, N: int) -> Tuple[Optional[Tuple[int, int]], Optional[int]]:
        """Computes k * P using double-and-add algorithm."""
        R = None
        current = P
        while k > 0:
            if k & 1:
                R, factor = self._point_add(R, current, a, N)
                if factor: return None, factor
            current, factor = self._point_add(current, current, a, N)
            if factor: return None, factor
            k >>= 1
        return R, None

    def factor(self, N: int, B1: int = 50, max_curves: int = 100) -> Dict:
        """Runs ECM with smoothness bound B1 across multiple curves."""
        # Check trivial cases
        if N % 2 == 0: return {"status": "SUCCESS", "factor": 2, "composite": N}

        # Build smooth multiplier k = ∏ p^a
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        k = 1
        for p in primes:
            if p > B1: break
            power = int(math.floor(math.log(B1) / math.log(p)))
            k *= (p ** power)

        curves_tried = 0
        for _ in range(max_curves):
            curves_tried += 1
            x = random.randint(1, N - 1)
            y = random.randint(1, N - 1)
            a = random.randint(1, N - 1)
            # b = y^2 - x^3 - a*x mod N
            b = (y * y - x * x * x - a * x) % N
            # Check curve singularity: 4a^3 + 27b^2 != 0 mod N
            disc = (4 * a**3 + 27 * b**2) % N
            g = math.gcd(disc, N)
            if 1 < g < N:
                return {"status": "SUCCESS", "factor": g, "composite": N, "curves_tested": curves_tried}

            P = (x, y)
            _, factor = self._scalar_multiply(k, P, a, N)
            if factor and 1 < factor < N:
                return {
                    "status": "SUCCESS",
                    "factor": factor,
                    "other_factor": N // factor,
                    "composite": N,
                    "curves_tested": curves_tried
                }

        return {"status": "FAILED", "composite": N, "curves_tested": curves_tried}

def run_tool():
    tool = LenstraECMFactoringTool()
    # Semiprime: 10403 = 101 * 103
    composite = 10403
    return tool.factor(composite, B1=50, max_curves=50)

if __name__ == "__main__":
    print(run_tool())
