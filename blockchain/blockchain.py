from blockchain.transaction import Transaction
from utils.crypto_utils import load_json, save_json
from blockchain.block import Block

# 区块链数据文件路径
BLOCKCHAIN_FILE = "data/blockchain.json"


class Blockchain:
    def __init__(self):
        # 初始化区块链为空列表
        self.chain = []
        # 加载现有区块链数据
        self.load_chain()

    def load_chain(self):
        # 从文件中加载区块链数据
        data = load_json(BLOCKCHAIN_FILE)
        if data:
            # 如果存在数据，则加载到链中
            self.chain = data
            return self.chain
        else:
            # 如果不存在数据，则创建创世区块
            genesis = Block(0, [], "0")
            self.chain.append(genesis.__dict__)
            # 保存创世区块到文件
            self.save_chain()

    def save_chain(self):
        # 将当前区块链保存到文件
        save_json(BLOCKCHAIN_FILE, self.chain)

    def add_block(self, transactions):
        # 验证所有交易
        for tx in transactions:
            # 如果交易对象不是 Transaction 类型，跳过或报错
            if not hasattr(tx, "is_valid"):
                raise TypeError("交易对象无效，必须是 Transaction 类型")
            if not tx.is_valid():
                raise ValueError(f"非法交易：{tx.from_addr} -> {tx.to_addr} 金额 {tx.amount}")

        # 获取前一个区块的哈希值
        prev_hash = self.chain[-1]['hash']
        # 创建新的区块
        block = Block(len(self.chain), transactions, prev_hash)
        # 将新区块添加到链中
        self.chain.append(block.__dict__)
        # 保存更新后的区块链到文件
        self.save_chain()

    def get_balance(self, address):
        # 计算指定地址的余额
        balance = 0
        # 遍历所有区块
        for block in self.chain:
            # 遍历每个区块中的所有交易
            for tx in block['transactions']:
                # 如果地址是发送方，则减去相应金额
                if tx['from'] == address:
                    balance -= tx['amount']
                # 如果地址是接收方，则加上相应金额
                if tx['to'] == address:
                    balance += tx['amount']
        return balance

    def faucet(self, address, amount=50):
        tx = Transaction("SYSTEM", address, amount, "SYSTEM")
        self.add_block([tx])


bc = Blockchain()
