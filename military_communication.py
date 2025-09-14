#!/usr/bin/env python3
"""
auth_enhanced_hybrid_crypto.py

Features:
 - AES-256-GCM (one-time key per message)
 - RSA-OAEP (wrap AES key)
 - Ed25519 (signature)
 - Unique message ID (UUID4)
 - Timestamp + TTL (self-destruct)
 - Metadata as AAD (sender_id, recipient_id, mission_tag)
 - Simple registry for recipients & senders (authorization / authentication)
 - JSON/base64 envelope for transport

Run: pip install cryptography
"""

import os
import time
import json
import base64
import uuid
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption
)

# -----------------------
# Simple in-memory registry (simulate auth server / key directory)
# -----------------------
# Structure:
# REGISTRY = {
#   "recipients": { recipient_id: recipient_pub_pem_str },
#   "senders":    { sender_id: sender_pub_pem_str }
# }
REGISTRY: Dict[str, Dict[str, str]] = {"recipients": {}, "senders": {}}


# -----------------------
# Key generation & IO
# -----------------------
def generate_rsa_keypair(key_size: int = 3072):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()
    return priv, pub

def generate_ed25519_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def pubkey_to_pem(public_key) -> str:
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")

def privkey_to_pem(private_key, password: Optional[bytes] = None) -> bytes:
    enc = BestAvailableEncryption(password) if password else NoEncryption()
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)

def load_pubkey_from_pem_str(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode("ascii"))

def load_privkey_from_pem_bytes(pem_bytes: bytes, password: Optional[bytes] = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)


# -----------------------
# Registry management
# -----------------------
def register_recipient(recipient_id: str, recipient_pub) -> None:
    """Store recipient's public key PEM in registry."""
    REGISTRY["recipients"][recipient_id] = pubkey_to_pem(recipient_pub)

def register_sender(sender_id: str, sender_pub) -> None:
    """Store sender's public key PEM in registry."""
    REGISTRY["senders"][sender_id] = pubkey_to_pem(sender_pub)

def is_recipient_authorized(recipient_id: str, recipient_pub) -> bool:
    """Check registry has the same public key for recipient_id."""
    stored = REGISTRY["recipients"].get(recipient_id)
    if not stored:
        return False
    return stored == pubkey_to_pem(recipient_pub)

def is_sender_known(sender_id: str, sender_pub) -> bool:
    stored = REGISTRY["senders"].get(sender_id)
    if not stored:
        return False
    return stored == pubkey_to_pem(sender_pub)


# -----------------------
# Helpers: base64 / json envelope
# -----------------------
def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def envelope_to_json(envelope: dict) -> str:
    return json.dumps(envelope)

def envelope_from_json(j: str) -> dict:
    return json.loads(j)


# -----------------------
# Encryption (sender)
# -----------------------
def encrypt_message(
    plaintext: bytes,
    recipient_rsa_pub,
    sender_ed25519_priv,
    sender_id: str,
    recipient_id: str,
    mission_tag: str,
    ttl: int = 30
) -> Dict:
    """
    Create an envelope. Metadata includes sender_id and recipient_id.
    The registry should already have recipient_id and sender_id registered.
    """
    # 1) Metadata
    msg_id = str(uuid.uuid4())
    timestamp = int(time.time())
    metadata = {
        "id": msg_id,
        "timestamp": timestamp,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "mission": mission_tag,
        "ttl": ttl
    }
    aad = json.dumps(metadata).encode("utf-8")

    # 2) One-time AES key
    aes_key = AESGCM.generate_key(bit_length=256)

    # 3) AES-GCM encrypt with AAD
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # 4) Wrap AES key with recipient RSA public key (OAEP)
    key_enc = recipient_rsa_pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    # 5) Sign (key_enc || nonce || ciphertext || aad)
    signed_blob = key_enc + nonce + ciphertext + aad
    signature = sender_ed25519_priv.sign(signed_blob)

    envelope = {
        "metadata": metadata,
        "key_enc": _b64(key_enc),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "signature": _b64(signature)
    }
    return envelope


# -----------------------
# Decryption (receiver)
# -----------------------
def decrypt_message(
    envelope: Dict,
    recipient_id: str,
    recipient_rsa_priv,
) -> bytes:
    """
    Checks:
      - envelope metadata recipient_id matches provided recipient_id
      - recipient_id is registered and public key matches the registry
      - sender_id is known (registered) and sender public key matches the registry
      - TTL not expired
      - signature valid
      - unwrap AES key and decrypt
    """
    metadata = envelope.get("metadata")
    if metadata is None:
        raise ValueError("Envelope missing metadata")

    # quick checks
    if metadata.get("recipient_id") != recipient_id:
        raise PermissionError("Envelope is not addressed to this recipient ID")

    # Verify recipient is authorized in registry: check stored public key equals recipient_priv's public
    recipient_pub = recipient_rsa_priv.public_key()
    if not is_recipient_authorized(recipient_id, recipient_pub):
        raise PermissionError("Recipient not authorized / not registered")

    # Check sender is known & get sender's public key
    sender_id = metadata.get("sender_id")
    sender_pub_pem = REGISTRY["senders"].get(sender_id)
    if not sender_pub_pem:
        raise PermissionError("Unknown sender ID (not registered)")

    sender_ed_pub = load_pubkey_from_pem_str(sender_pub_pem)

    # TTL check
    now = int(time.time())
    if now > metadata["timestamp"] + metadata["ttl"]:
        raise ValueError(f"Message expired (self-destruct). ID={metadata.get('id')}")

    # Reconstruct byte fields
    key_enc = _unb64(envelope["key_enc"])
    nonce = _unb64(envelope["nonce"])
    ciphertext = _unb64(envelope["ciphertext"])
    signature = _unb64(envelope["signature"])
    aad = json.dumps(metadata).encode("utf-8")

    # Verify signature (will raise InvalidSignature if invalid)
    signed_blob = key_enc + nonce + ciphertext + aad
    sender_ed_pub.verify(signature, signed_blob)

    # Unwrap AES key with recipient RSA private key
    aes_key = recipient_rsa_priv.decrypt(
        key_enc,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    # Decrypt AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext


# -----------------------
# Example usage
# -----------------------
def example_run():
    # create keys for recipient and sender
    recipient_rsa_priv, recipient_rsa_pub = generate_rsa_keypair()
    sender_ed_priv, sender_ed_pub = generate_ed25519_keypair()
    # also create an RSA keypair for sender if you want sender to have RSA for other purposes; not needed here

    # IDs
    recipient_id = "Unit-007"
    sender_id = "Operator-A"

    # Register both in the (simulated) registry
    register_recipient(recipient_id, recipient_rsa_pub)
    register_sender(sender_id, sender_ed_pub)

    print("Registry entries created:")
    print(" Recipients:", list(REGISTRY["recipients"].keys()))
    print(" Senders:", list(REGISTRY["senders"].keys()))

    # Sender encrypts message addressed to recipient_id
    plaintext = b"Attack at dawn. Code: 7-7-7."
    envelope = encrypt_message(
        plaintext=plaintext,
        recipient_rsa_pub=recipient_rsa_pub,
        sender_ed25519_priv=sender_ed_priv,
        sender_id=sender_id,
        recipient_id=recipient_id,
        mission_tag="Op-Silent",
        ttl=10  # seconds
    )

    print("\nEnvelope metadata:", envelope["metadata"])
    # Save/transfer envelope (as JSON) simulated by variable passing here

    # Recipient receives and attempts to decrypt
    try:
        recovered = decrypt_message(envelope, recipient_id, recipient_rsa_priv)
        print("\nDecrypted plaintext:", recovered.decode("utf-8"))
    except Exception as e:
        print("\nDecryption failed:", type(e)._name_, str(e))

    # Simulate unauthorized recipient attempt with different key
    fake_priv, fake_pub = generate_rsa_keypair()
    fake_recipient_id = "Unit-999"
    print("\nSimulating unauthorized recipient...")
    try:
        decrypt_message(envelope, fake_recipient_id, fake_priv)
    except Exception as e:
        print("Unauthorized decrypt attempt result:", type(e)._name_, str(e))

    # Simulate expiry
    print("\nWaiting for TTL to expire...")
    time.sleep(11)
    try:
        decrypt_message(envelope, recipient_id, recipient_rsa_priv)
    except Exception as e:
        print("After expiry:", type(e)._name_, str(e))


if _name_ == "_main_":
    example_run()
