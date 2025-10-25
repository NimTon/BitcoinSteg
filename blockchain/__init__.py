# blockchain/__init__.py
from .blockchain import Blockchain
from .transaction import Transaction
from .block import Block

# 全局唯一区块链实例
blockchain = Blockchain()
