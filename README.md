# Cryptanalysis Package

**Roll No:** 24pc20  
**Name:** Pranay Shaunjay P.V  

---

## Abstract
This package provides a unified, educational cryptanalysis suite implemented in pure Python, systematically covering the theoretical and practical dimensions of Course Outcomes **CO3**, **CO4**, and **CO5**:
1. **CO3 (Block Ciphers, Side-Channels, Quantum & Hash Functions):**
   Explores differential and linear cryptanalysis (DDT and LAT generation), statistical timing side-channel exploitation, AES Differential Fault Analysis (DFA), Grover's quantum key search simulation, Floyd's cycle-finding birthday collision attacks on hashes and digital signatures, and Merkle-Damgård / MD4 length extension attacks.
2. **CO4 (Public-Key Cryptosystems, Lattices, Provable Security & Factoring):**
   Covers lattice basis reduction (Lenstra-Lenstra-Lovász / LLL algorithm) against the Merkle-Hellman Knapsack cryptosystem, the formal IND-CPA security game for deterministic vs randomized encryption, adaptive chosen ciphertext (IND-CCA2) attacks on malleable ElGamal versus Cramer-Shoup non-malleability, the Random Oracle Model (ROM) and Fiat-Shamir transformation, ElGamal signature ephemeral nonce reuse private key recovery, Lenstra's Elliptic Curve Method (ECM) integer factorization, and Bilinear Pairing Decisional Diffie-Hellman (DDH) solvers.
3. **CO5 (Authentication Protocols, Attacker Models & Formal Analysis):**
   Implements the formal Dolev-Yao threat model network simulator, the classic Denning-Sacco replay attack on the Needham-Schroeder symmetric protocol along with timestamped countermeasures, active Man-in-the-Middle (MitM) parameter injection on Diffie-Hellman, symmetric challenge-response reflection attacks, and Burrows-Abadi-Needham (BAN) modal logic automated deduction.

---

## Directory Structure
```
cryptanalysis_package/
├── main.py
├── README.md
└── cryptanalysis/
    ├── __init__.py
    ├── co3_block_sidechannel_hash/
    │   ├── __init__.py
    │   ├── tool01_ddt_differential.py
    │   ├── tool02_lat_linear.py
    │   ├── tool03_timing_sidechannel.py
    │   ├── tool04_fault_injection_aes.py
    │   ├── tool05_grover_quantum_search.py
    │   ├── tool06_birthday_hash_collision.py
    │   ├── tool07_birthday_signature_forgery.py
    │   └── tool08_md4_length_extension.py
    ├── co4_asymmetric_lattices_factoring/
    │   ├── __init__.py
    │   ├── tool09_knapsack_lll_lattice.py
    │   ├── tool10_ind_cpa_security_game.py
    │   ├── tool11_ind_cca2_elgamal_cramer_shoup.py
    │   ├── tool12_random_oracle_fiat_shamir.py
    │   ├── tool13_elgamal_nonce_reuse.py
    │   ├── tool14_lenstra_ecm_factoring.py
    │   └── tool15_bilinear_pairing_ddh.py
    └── co5_protocol_attacker_formal/
        ├── __init__.py
        ├── tool16_dolev_yao_network_simulator.py
        ├── tool17_needham_schroeder_replay.py
        ├── tool18_diffie_hellman_mitm.py
        ├── tool19_reflection_attack_simulator.py
        └── tool20_ban_logic_verifier.py
```

## How to Run
Run the master verification test harness:
```bash
python main.py
```
Or execute individual tools, e.g.:
```bash
python cryptanalysis/co3_block_sidechannel_hash/tool01_ddt_differential.py
python cryptanalysis/co4_asymmetric_lattices_factoring/tool09_knapsack_lll_lattice.py
python cryptanalysis/co5_protocol_attacker_formal/tool20_ban_logic_verifier.py
```
