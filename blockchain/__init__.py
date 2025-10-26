# blockchain/__init__.py
from .blockchain import Blockchain
from .transaction_pool import TransactionPool

# 全局唯一区块链实例
blockchain = Blockchain()
transaction_pool = TransactionPool()