import time
import json
import hashlib
from config import MINING_DIFFICULTY
from utils.utils_block import compute_merkle_root


class Block:
    def __init__(self, index, transactions, previous_hash, timestamp=None):
        """
        初始化区块
        
        Args:
            index: 区块索引号
            transactions: 交易列表
            previous_hash: 前一区块的哈希值
            timestamp: 时间戳，默认为当前时间
        """
        self.index = index
        self.transactions = [tx.to_dict() for tx in transactions]
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.nonce = 0
        tx_hashes = [tx['hash'] for tx in self.transactions]
        self.merkle_root = compute_merkle_root(tx_hashes)
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """
        计算区块的哈希值
        
        Returns:
            str: 区块的SHA256哈希值
        """
        # 将区块数据转换为字符串并排序以确保一致性
        block_string = json.dumps({
            'index': self.index,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }, sort_keys=True)
        # 使用SHA256算法计算哈希值
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine(self, difficulty=None, max_attempts=None):
        """
        简单的 PoW 矿工：调整 nonce 直到 hash 前缀满足要求。
        difficulty: 前缀为多少个 '0'（十六进制字符）。
        max_attempts: 可选，最大尝试次数，避免无限循环。
        返回找到的 hash。
        """
        if difficulty is None:
            difficulty = MINING_DIFFICULTY
        assert difficulty >= 0
        target_prefix = '0' * difficulty
        attempts = 0
        while True:
            self.hash = self.calculate_hash()
            if self.hash.startswith(target_prefix):
                return self.hash
            self.nonce += 1
            attempts += 1
            if max_attempts is not None and attempts >= max_attempts:
                raise RuntimeError(f"Mining failed after {attempts} attempts")
