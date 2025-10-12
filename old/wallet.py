from ecdsa import SigningKey, SECP256k1
from utils.utils import hash160, base58_encode, calculate_checksum

class Wallet:
    def __init__(self, sk_hex=None):
        if sk_hex:
            self.private_key = SigningKey.from_string(bytes.fromhex(sk_hex), curve=SECP256k1)
        else:
            self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def get_address(self) -> str:
        pubkey_bytes = self.public_key.to_string()
        h160 = hash160(pubkey_bytes)
        versioned_payload = b'\x00' + h160
        checksum = calculate_checksum(versioned_payload)
        return base58_encode(versioned_payload + checksum)
