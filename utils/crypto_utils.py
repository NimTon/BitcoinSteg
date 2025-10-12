import json
import os
import hashlib
from ecdsa import SigningKey, SECP256k1, VerifyingKey

def generate_keypair():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    private_key = sk.to_string().hex()
    public_key = vk.to_string().hex()
    address = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:16]
    return private_key, public_key, address

def sign_message(private_key_hex, message):
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    signature = sk.sign(message.encode())
    return signature.hex()

def verify_signature(public_key_hex, message, signature_hex):
    vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
    try:
        return vk.verify(bytes.fromhex(signature_hex), message.encode())
    except:
        return False

def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return {}

def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)
