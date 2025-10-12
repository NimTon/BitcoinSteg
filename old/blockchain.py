import json
import hashlib
from transaction import Transaction

BLOCKCHAIN_FILE = "blockchain.json"

class Block:
    def __init__(self, index, transactions, prev_hash="0"*64):
        self.index = index
        self.transactions = transactions  # list of Transaction dicts
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        tx_str = json.dumps([tx.__dict__ for tx in self.transactions], sort_keys=True)
        return hashlib.sha256(f'{self.index}{tx_str}{self.prev_hash}'.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = self.load_chain()

    def load_chain(self):
        try:
            with open(BLOCKCHAIN_FILE, "r") as f:
                data = json.load(f)
                return data
        except FileNotFoundError:
            return []

    def save_chain(self):
        with open(BLOCKCHAIN_FILE, "w") as f:
            json.dump(self.chain, f, indent=4)

    def add_block(self, block: Block):
        self.chain.append(block.__dict__)
        self.save_chain()

    def last_block_hash(self):
        return self.chain[-1]['hash'] if self.chain else "0"*64
