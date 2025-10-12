import os
import json
from block import Block
from transaction import Transaction   # ✅ 一定要导入 Transaction

DATA_FILE = "data/blockchain.json"


class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

        # 如果文件不存在或为空链，则自动创建创世块
        if not self.chain:
            self.create_genesis_block()

    def create_genesis_block(self):
        """创建创世块"""
        genesis = Block(0, "0", [])
        genesis.mine_block()
        self.chain.append(genesis)
        self.save_chain()

    def add_block(self, transactions):
        """添加新区块"""
        prev_hash = self.chain[-1].hash if self.chain else "0"
        block = Block(len(self.chain), prev_hash, transactions)
        block.mine_block()
        self.chain.append(block)
        self.save_chain()

    def save_chain(self):
        """保存区块链到文件"""
        os.makedirs("data", exist_ok=True)
        chain_data = []
        for b in self.chain:
            chain_data.append({
                "index": b.index,
                "prev_hash": b.prev_hash,
                "timestamp": b.timestamp,
                "nonce": b.nonce,
                "hash": b.hash,
                "transactions": [tx.to_dict() for tx in b.transactions],
            })

        with open(DATA_FILE, "w") as f:
            json.dump(chain_data, f, indent=2)

    def load_chain(self):
        """从文件加载区块链"""
        if not os.path.exists(DATA_FILE):
            return  # 文件不存在则不加载

        with open(DATA_FILE, "r") as f:
            data = json.load(f)
            for b in data:
                # ✅ 使用 Transaction.from_dict() 恢复每笔交易
                transactions = [Transaction.from_dict(tx_data) for tx_data in b.get("transactions", [])]

                block = Block(b["index"], b["prev_hash"], transactions)
                block.timestamp = b["timestamp"]
                block.nonce = b["nonce"]
                block.hash = b["hash"]
                self.chain.append(block)
