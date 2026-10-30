"""
Tool 20: BAN (Burrows-Abadi-Needham) Logic Formal Verification Engine
Course Outcome: CO5 (Formal Analysis of Authentication and Key-Exchange Protocols)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

from typing import List, Set, Tuple, Dict

class BANLogicFormalVerifier:
    """
    Formal logic deduction engine implementing Burrows-Abadi-Needham (BAN) Logic for authentication protocols.
    Symbols and constructs:
      - Believes(P, X)          : P believes X
      - Sees(P, X)              : P sees / receives X
      - Said(P, X)              : P once said X
      - Fresh(X)                : X is fresh (nonce / timestamp)
      - KeyShared(P, Q, K)      : K is a good shared secret between P and Q
      - Controls(P, X)          : P has jurisdiction over X
    Deduction Rules implemented:
      1. Message Meaning: Believes(P, KeyShared(P, Q, K)) ∧ Sees(P, Encrypted(X, K)) => Believes(P, Said(Q, X))
      2. Nonce Verification: Believes(P, Fresh(X)) ∧ Believes(P, Said(Q, X)) => Believes(P, Believes(Q, X))
      3. Jurisdiction: Believes(P, Controls(Q, X)) ∧ Believes(P, Believes(Q, X)) => Believes(P, X)
    """
    def __init__(self):
        self.beliefs: Set[str] = set()
        self.deduction_trace: List[str] = []

    def assert_belief(self, fact: str):
        self.beliefs.add(fact)

    def apply_inference_rules(self, max_passes: int = 5) -> None:
        """Applies BAN deduction rules iteratively until fixed point is reached."""
        for _ in range(max_passes):
            new_inferences = set()

            # Rule 1: Message Meaning
            # P believes P <-> Q with K, and P sees {X}_K -> P believes Q said X
            for b in list(self.beliefs):
                if b.startswith("SharedKey("):
                    # Format: SharedKey(P,Q,K)
                    parts = b[len("SharedKey("):-1].split(",")
                    p, q, k = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    # Check if P sees Encrypted(X, K)
                    for b2 in list(self.beliefs):
                        prefix = f"Sees({p},Encrypted("
                        if b2.startswith(prefix) and b2.endswith(f",{k}))"):
                            x = b2[len(prefix):-(len(k) + 2)]
                            fact = f"Believes({p},Said({q},{x}))"
                            if fact not in self.beliefs:
                                new_inferences.add(fact)
                                self.deduction_trace.append(f"Message-Meaning-Rule => {fact}")

            # Rule 2: Nonce-Verification Rule
            # P believes Fresh(X), and P believes Q said X -> P believes Q believes X
            for b in list(self.beliefs):
                if b.startswith("Believes(") and ",Said(" in b:
                    # Format: Believes(P,Said(Q,X))
                    inner = b[len("Believes("):-1]
                    p, rest = inner.split(",Said(", 1)
                    q, x = rest.split(",", 1)
                    x = x[:-1]
                    fresh_assertion = f"Believes({p},Fresh({x}))"
                    if fresh_assertion in self.beliefs:
                        fact = f"Believes({p},Believes({q},{x}))"
                        if fact not in self.beliefs:
                            new_inferences.add(fact)
                            self.deduction_trace.append(f"Nonce-Verification-Rule => {fact}")

            # Rule 3: Jurisdiction Rule
            # P believes Q controls X, and P believes Q believes X -> P believes X
            for b in list(self.beliefs):
                if b.startswith("Believes(") and ",Controls(" in b:
                    inner = b[len("Believes("):-1]
                    p, rest = inner.split(",Controls(", 1)
                    q, x = rest.split(",", 1)
                    x = x[:-1]
                    q_believes = f"Believes({p},Believes({q},{x}))"
                    if q_believes in self.beliefs:
                        fact = f"Believes({p},{x})"
                        if fact not in self.beliefs:
                            new_inferences.add(fact)
                            self.deduction_trace.append(f"Jurisdiction-Rule => {fact}")

            if not new_inferences:
                break
            self.beliefs.update(new_inferences)

    def verify_goal(self, goal: str) -> bool:
        return goal in self.beliefs

def run_tool():
    verifier = BANLogicFormalVerifier()

    # Initial Assumptions for Needham-Schroeder / Kerberos Key Exchange
    verifier.assert_belief("SharedKey(Alice,Server,Kas)")
    verifier.assert_belief("SharedKey(Server,Alice,Kas)")
    verifier.assert_belief("Believes(Alice,Fresh(Na))")
    verifier.assert_belief("Believes(Alice,Controls(Server,SharedKey(Alice,Bob,Kab)))")

    # Step: Alice sees ticket encrypted with Kas containing session key Kab and fresh Na
    verifier.assert_belief("Sees(Alice,Encrypted(SharedKey(Alice,Bob,Kab),Kas))")
    verifier.assert_belief("Believes(Alice,Fresh(SharedKey(Alice,Bob,Kab)))")

    # Execute BAN deduction engine
    verifier.apply_inference_rules()

    target_goal = "Believes(Alice,SharedKey(Alice,Bob,Kab))"
    proven = verifier.verify_goal(target_goal)

    return {
        "status": "SUCCESS",
        "target_security_goal": target_goal,
        "formally_proven": proven,
        "deduction_steps": verifier.deduction_trace,
        "formal_conclusion": "Goal satisfied: Alice formally establishes authentic belief in session key Kab." if proven else "Formal verification failed."
    }

if __name__ == "__main__":
    print(run_tool())
