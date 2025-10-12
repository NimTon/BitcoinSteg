from utils.crypto_utils import load_json, save_json
from blockchain.block import Block

BLOCKCHAIN_FILE = "data/blockchain.json"

class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

    def load_chain(self):
        data = load_json(BLOCKCHAIN_FILE)
        if data:
            self.chain = data
        else:
            genesis = Block(0, [], "0")
            self.chain.append(genesis.__dict__)
            self.save_chain()

    def save_chain(self):
        save_json(BLOCKCHAIN_FILE, self.chain)

    def add_block(self, transactions):
        prev_hash = self.chain[-1]['hash']
        from .transaction import Transaction
        block = Block(len(self.chain), transactions, prev_hash)
        self.chain.append(block.__dict__)
        self.save_chain()

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block['transactions']:
                if tx['from'] == address:
                    balance -= tx['amount']
                if tx['to'] == address:
                    balance += tx['amount']
        return balance
