"""
Cryptanalysis Package Test & Demonstration Harness
Heading: Cryptanalysis package | Roll No: 24pc20 | Name: Pranay Shaunjay P.V

Runs and validates all 20 cryptanalytic tool implementations across CO3, CO4, and CO5.
"""

import sys
import os

# Add parent directory to path so imports work cleanly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptanalysis.co3_block_sidechannel_hash import (
    tool01_ddt_differential,
    tool02_lat_linear,
    tool03_timing_sidechannel,
    tool04_fault_injection_aes,
    tool05_grover_quantum_search,
    tool06_birthday_hash_collision,
    tool07_birthday_signature_forgery,
    tool08_md4_length_extension
)

from cryptanalysis.co4_asymmetric_lattices_factoring import (
    tool09_knapsack_lll_lattice,
    tool10_ind_cpa_security_game,
    tool11_ind_cca2_elgamal_cramer_shoup,
    tool12_random_oracle_fiat_shamir,
    tool13_elgamal_nonce_reuse,
    tool14_lenstra_ecm_factoring,
    tool15_bilinear_pairing_ddh
)

from cryptanalysis.co5_protocol_attacker_formal import (
    tool16_dolev_yao_network_simulator,
    tool17_needham_schroeder_replay,
    tool18_diffie_hellman_mitm,
    tool19_reflection_attack_simulator,
    tool20_ban_logic_verifier
)

def run_all_tools():
    tools = [
        ("Tool 01 (CO3)", "S-Box Difference Distribution Table (DDT)", tool01_ddt_differential.run_tool),
        ("Tool 02 (CO3)", "S-Box Linear Approximation Table (LAT)", tool02_lat_linear.run_tool),
        ("Tool 03 (CO3)", "Statistical Timing Side-Channel Analyzer", tool03_timing_sidechannel.run_tool),
        ("Tool 04 (CO3)", "AES Differential Fault Analysis (DFA) Simulator", tool04_fault_injection_aes.run_tool),
        ("Tool 05 (CO3)", "Quantum Key Search (Grover's Algorithm)", tool05_grover_quantum_search.run_tool),
        ("Tool 06 (CO3)", "Hash Birthday Collision Engine (Pollard's Rho)", tool06_birthday_hash_collision.run_tool),
        ("Tool 07 (CO3)", "Digital Signature Birthday Forgery Engine", tool07_birthday_signature_forgery.run_tool),
        ("Tool 08 (CO3)", "MD4 / Merkle-Damgard Length Extension Attack", tool08_md4_length_extension.run_tool),

        ("Tool 09 (CO4)", "Merkle-Hellman Knapsack Lattice Reduction (LLL)", tool09_knapsack_lll_lattice.run_tool),
        ("Tool 10 (CO4)", "IND-CPA Semantic Security Adversary Game", tool10_ind_cpa_security_game.run_tool),
        ("Tool 11 (CO4)", "IND-CCA2 Security Evaluator (ElGamal vs Cramer-Shoup)", tool11_ind_cca2_elgamal_cramer_shoup.run_tool),
        ("Tool 12 (CO4)", "Random Oracle Model / Fiat-Shamir Simulator", tool12_random_oracle_fiat_shamir.run_tool),
        ("Tool 13 (CO4)", "ElGamal Signature Nonce-Reuse Private Key Extractor", tool13_elgamal_nonce_reuse.run_tool),
        ("Tool 14 (CO4)", "Lenstra's Elliptic Curve Method (ECM) Factoring", tool14_lenstra_ecm_factoring.run_tool),
        ("Tool 15 (CO4)", "Bilinear Pairing Decisional Diffie-Hellman Solver", tool15_bilinear_pairing_ddh.run_tool),

        ("Tool 16 (CO5)", "Dolev-Yao Threat Model Network Simulator", tool16_dolev_yao_network_simulator.run_tool),
        ("Tool 17 (CO5)", "Needham-Schroeder Replay & Denning-Sacco Fix", tool17_needham_schroeder_replay.run_tool),
        ("Tool 18 (CO5)", "Diffie-Hellman Active Man-in-the-Middle (MitM) Engine", tool18_diffie_hellman_mitm.run_tool),
        ("Tool 19 (CO5)", "Symmetric Challenge-Response Reflection Attack", tool19_reflection_attack_simulator.run_tool),
        ("Tool 20 (CO5)", "BAN Logic Formal Verification Engine", tool20_ban_logic_verifier.run_tool),
    ]

    print("=" * 80)
    print(" Cryptanalysis package | Roll No: 24pc20 | Name: Pranay Shaunjay P.V")
    print("=" * 80)

    passed = 0
    for idx, name, func in tools:
        try:
            res = func()
            print(f"[{idx}] {name:<55} -> SUCCESS")
            passed += 1
        except Exception as e:
            print(f"[{idx}] {name:<55} -> FAILED ({e})")

    print("=" * 80)
    print(f"Summary: {passed} / {len(tools)} Cryptanalysis Tools Executed Successfully!")
    print("=" * 80)

if __name__ == "__main__":
    run_all_tools()
