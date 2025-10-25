from utils.utils_crypto import verify_signature, get_public_key_from_address
import hashlib, json


class Transaction:
    def __init__(self, from_addr, to_addr, amount, signature):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.amount = amount
        self.signature = signature
        self.hash = self.compute_hash()
        self.from_pubkey = get_public_key_from_address(self.from_addr)
        self.to_pubkey = get_public_key_from_address(self.to_addr)

    def to_dict(self):
        return {
            'from': self.from_addr,
            'to': self.to_addr,
            'amount': self.amount,
            'signature': self.signature,
            'hash': self.hash
        }

    def to_message(self):
        return f"{self.from_addr}->{self.to_addr}:{self.amount}"

    def is_valid(self):
        # 使用交易里的公钥验证签名
        if not self.from_pubkey:
            return False

        return verify_signature(self.from_pubkey, self.to_message(), self.signature)

    def compute_hash(self):
        tx_str = json.dumps({
            "from": self.from_addr,
            "to": self.to_addr,
            "amount": self.amount,
            "signature": self.signature
        }, sort_keys=True)
        return hashlib.sha256(tx_str.encode()).hexdigest()
