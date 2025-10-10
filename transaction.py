from utils.crypto_utils import tx_hash, aes_encrypt, CONFIG, random_amount


class Transaction:
    def __init__(self, sender, receiver, amount=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount or random_amount()
        self.hash = tx_hash(sender, receiver, self.amount)
        self.encrypted = aes_encrypt(self.hash, CONFIG["AES_KEY"])

    def __repr__(self):
        return f"Transaction({self.sender} -> {self.receiver}, {self.amount})"

    def to_dict(self):
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "hash": self.hash,
            "encrypted": self.encrypted
        }
