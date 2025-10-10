from block import Block
import json, os

DATA_FILE = "data/blockchain.json"

class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

    def create_genesis_block(self):
        genesis = Block(0, "0", [])
        genesis.mine_block()
        self.chain.append(genesis)
        self.save_chain()

    def add_block(self, transactions):
        prev_hash = self.chain[-1].hash if self.chain else "0"
        block = Block(len(self.chain), prev_hash, transactions)
        block.mine_block()
        self.chain.append(block)
        self.save_chain()

    def save_chain(self):
        import os, json
        os.makedirs("data", exist_ok=True)
        chain_data = []
        for b in self.chain:
            chain_data.append({
                "index": b.index,
                "prev_hash": b.prev_hash,
                "timestamp": b.timestamp,
                "nonce": b.nonce,
                "hash": b.hash,
                "transactions": [tx.to_dict() for tx in b.transactions]
            })
        with open(DATA_FILE, "w") as f:
            json.dump(chain_data, f, indent=2)

    def load_chain(self):
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
                for b in data:
                    block = Block(b['index'], b['prev_hash'], [])
                    block.timestamp = b['timestamp']
                    block.nonce = b['nonce']
                    block.hash = b['hash']
                    self.chain.append(block)
