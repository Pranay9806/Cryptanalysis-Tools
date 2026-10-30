"""
Tool 18: Man-in-the-Middle (MitM) & Parameter Injection Engine for Diffie-Hellman
Course Outcome: CO5 (Key-Exchange Protocols - Man-in-the-Middle Attacks)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import random
from typing import Dict, Tuple

class DiffieHellmanMitmTool:
    """
    Demonstrates active Man-in-the-Middle (MitM) attack on unauthenticated Diffie-Hellman Key Exchange.
    Without mutual authentication (e.g. digital signatures or pre-shared certificates):
      1. Alice sends public key A = g^a mod p.
      2. Eve intercepts A, and transmits forged key E = g^e mod p to Bob.
      3. Bob sends public key B = g^b mod p.
      4. Eve intercepts B, and transmits forged key E = g^e mod p to Alice.
      5. Alice establishes key K_AE = E^a = g^{ea}.
      6. Bob establishes key K_EB = E^b = g^{eb}.
      7. Eve computes both K_AE and K_EB, allowing seamless decryption, inspection, and spoofing.
    """
    def __init__(self, p: int = 10007, g: int = 5):
        self.p = p
        self.g = g

    def simulate_mitm_attack(self, alice_secret_msg: str = "CONFIDENTIAL_PAYLOAD_TRANSFER") -> Dict:
        # Alice generates ephemeral private and public key
        a = random.randint(2, self.p - 2)
        A = pow(self.g, a, self.p)

        # Bob generates ephemeral private and public key
        b = random.randint(2, self.p - 2)
        B = pow(self.g, b, self.p)

        # Eve generates active MitM private and public key
        e = random.randint(2, self.p - 2)
        E = pow(self.g, e, self.p)

        # In-transit interception:
        # Alice receives E instead of B
        # Bob receives E instead of A
        key_alice = pow(E, a, self.p)
        key_bob = pow(E, b, self.p)

        # Eve computes both shared secrets
        key_eve_with_alice = pow(A, e, self.p)
        key_eve_with_bob = pow(B, e, self.p)

        # Alice encrypts message intended for Bob using key_alice
        alice_ciphertext = [ord(ch) ^ (key_alice & 0xFF) for ch in alice_secret_msg]

        # Eve intercepts ciphertext, decrypts with key_eve_with_alice
        eve_decrypted_msg = "".join(chr(byte ^ (key_eve_with_alice & 0xFF)) for byte in alice_ciphertext)

        # Eve modifies message and re-encrypts using key_eve_with_bob
        tampered_msg = eve_decrypted_msg.replace("CONFIDENTIAL", "TAMPERED_FRAUDULENT")
        tampered_ciphertext = [ord(ch) ^ (key_eve_with_bob & 0xFF) for ch in tampered_msg]

        # Bob decrypts tampered message using key_bob
        bob_received_msg = "".join(chr(byte ^ (key_bob & 0xFF)) for byte in tampered_ciphertext)

        return {
            "status": "SUCCESS",
            "alice_established_key": key_alice,
            "bob_established_key": key_bob,
            "eve_alice_key": key_eve_with_alice,
            "eve_bob_key": key_eve_with_bob,
            "keys_compromised": (key_alice == key_eve_with_alice) and (key_bob == key_eve_with_bob),
            "original_alice_message": alice_secret_msg,
            "eve_intercepted_message": eve_decrypted_msg,
            "bob_received_message": bob_received_msg
        }

def run_tool():
    tool = DiffieHellmanMitmTool()
    return tool.simulate_mitm_attack()

if __name__ == "__main__":
    print(run_tool())
