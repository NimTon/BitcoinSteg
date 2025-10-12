class Transaction:
    def __init__(self, from_addr, to_addr, amount, signature):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            'from': self.from_addr,
            'to': self.to_addr,
            'amount': self.amount,
            'signature': self.signature
        }
