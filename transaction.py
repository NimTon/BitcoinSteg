from utils.crypto_utils import tx_hash, aes_encrypt, CONFIG, random_amount


class Transaction:
    def __init__(self, sender, receiver, amount=None, hash_value=None, encrypted=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.hash = hash_value
        self.encrypted = encrypted

    def to_dict(self):
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "hash": self.hash,
            "encrypted": self.encrypted,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            sender=data["sender"],
            receiver=data["receiver"],
            amount=data["amount"],
            hash_value=data.get("hash"),
            encrypted=data.get("encrypted"),
        )
