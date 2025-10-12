import time
import json
import hashlib

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
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }, sort_keys=True)
        # 使用SHA256算法计算哈希值
        return hashlib.sha256(block_string.encode()).hexdigest()
