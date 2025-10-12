from ecdsa import VerifyingKey

class Transaction:
    def __init__(self, sender_pub, recipient_addr, amount):
        self.sender_pub = sender_pub
        self.recipient_addr = recipient_addr
        self.amount = amount
        self.signature = None

    def sign(self, sender_sk):
        msg = f'{self.sender_pub.to_string().hex()}->{self.recipient_addr}:{self.amount}'.encode()
        self.signature = sender_sk.sign(msg).hex()
        return self.signature

    def verify(self):
        vk = self.sender_pub
        msg = f'{vk.to_string().hex()}->{self.recipient_addr}:{self.amount}'.encode()
        return vk.verify(bytes.fromhex(self.signature), msg)
