import hashlib, json, time

class Block:
    def __init__(self, index, prev_hash, transactions):
        self.index = index
        self.prev_hash = prev_hash
        self.timestamp = int(time.time())
        self.transactions = transactions
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "transactions": [t.encrypted for t in self.transactions],
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty=2):
        prefix = "0" * difficulty
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()
