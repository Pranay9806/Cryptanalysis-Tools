"""
Tool 16: Dolev-Yao Threat Model Network Simulator
Course Outcome: CO5 (Attacker model - Dolev-Yao Model & Basic Protocols)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

from typing import List, Dict, Any, Optional

class DolevYaoNetworkSimulator:
    """
    Simulates the formal Dolev-Yao Attacker Model (1983):
      1. The attacker can eavesdrop on any transmitted message.
      2. The attacker is a full active man-in-the-middle: can delay, drop, or duplicate messages.
      3. The attacker can synthesize new messages from its accumulated knowledge base.
      4. Cryptographic primitives are treated as perfect black boxes: an attacker cannot decrypt
         without having the secret key, nor can they forge a signature without the private key.
    """
    def __init__(self):
        self.channel_buffer: List[Dict[str, Any]] = []
        self.attacker_knowledge: set = set()
        self.intercepted_history: List[Dict[str, Any]] = []

    def transmit(self, sender: str, receiver: str, payload: Dict[str, Any]) -> None:
        """Legitimate message sent over the insecure channel."""
        message = {
            "sender": sender,
            "receiver": receiver,
            "payload": payload,
            "tampered": False
        }
        self.channel_buffer.append(message)

    def attacker_eavesdrop_and_intercept(self) -> Optional[Dict[str, Any]]:
        """Attacker intercepts the pending message from the channel."""
        if not self.channel_buffer:
            return None
        msg = self.channel_buffer.pop(0)
        self.intercepted_history.append(msg)

        # Harvest plaintext knowledge
        for k, v in msg["payload"].items():
            if isinstance(v, (str, int)):
                self.attacker_knowledge.add(f"{k}:{v}")
        return msg

    def attacker_inject_forged_message(self, spoofed_sender: str, receiver: str, forged_payload: Dict[str, Any]) -> None:
        """Attacker injects a synthetic message masquerading as the spoofed sender."""
        forged_message = {
            "sender": spoofed_sender,
            "receiver": receiver,
            "payload": forged_payload,
            "tampered": True
        }
        self.channel_buffer.append(forged_message)

    def deliver_to_receiver(self, expected_receiver: str) -> Optional[Dict[str, Any]]:
        """Receiver pops incoming message from the channel."""
        for i, msg in enumerate(self.channel_buffer):
            if msg["receiver"] == expected_receiver:
                return self.channel_buffer.pop(i)
        return None

def run_tool():
    net = DolevYaoNetworkSimulator()

    # Alice sends sensitive authentication token to Bob
    net.transmit(sender="Alice", receiver="Bob", payload={"action": "login", "nonce": 98765, "auth": "AliceToken"})

    # Dolev-Yao Attacker intercepts message
    intercepted = net.attacker_eavesdrop_and_intercept()

    # Attacker crafts malicious payload modifying the action
    net.attacker_inject_forged_message(
        spoofed_sender="Alice",
        receiver="Bob",
        forged_payload={"action": "drain_funds", "account": "Attacker_Wallet", "nonce": 98765}
    )

    # Bob receives the delivered packet
    bob_received = net.deliver_to_receiver("Bob")

    return {
        "status": "SUCCESS",
        "intercepted_by_attacker": intercepted,
        "attacker_harvested_knowledge": list(net.attacker_knowledge),
        "bob_received_message": bob_received,
        "compromise_summary": "Attacker successfully suppressed Alice's message and injected arbitrary forged payload."
    }

if __name__ == "__main__":
    print(run_tool())
