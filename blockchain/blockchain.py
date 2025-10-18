from blockchain.transaction import Transaction
from utils.utils_crypto import load_json, save_json
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

    def add_block(self, transactions, timestamp=None):
        self.load_chain()
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
        block = Block(len(self.chain), transactions, prev_hash, timestamp=timestamp)
        # 将新区块添加到链中
        self.chain.append(block.__dict__)
        # 保存更新后的区块链到文件
        self.save_chain()
        return block

    def get_balance(self, address):
        self.load_chain()
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

    def get_transactions_by_address(self, address):
        """
        获取与某个地址相关的所有交易（作为发送方或接收方）
        返回列表，每个元素是交易字典（含所在区块高度和哈希）
        """
        self.load_chain()
        related_txs = []
        for block in self.chain:
            block_height = block.get("index", 0)
            block_hash = block.get("hash", "")
            for tx in block['transactions']:
                if tx['from'] == address or tx['to'] == address:
                    tx_info = {
                        "block_height": block_height,
                        "block_hash": block_hash,
                        "tx_hash": tx.get("tx_hash", ""),  # 如果交易中没有tx_hash，可改为计算逻辑
                        "from": tx['from'],
                        "to": tx['to'],
                        "amount": tx['amount']
                    }
                    related_txs.append(tx_info)
        return related_txs

    def get_all_transactions(self, user=None):
        """
        获取系统中所有交易。
        若传入 user 对象，则返回与 user 相关（其所有地址）的交易。
        """
        self.load_chain()
        all_txs = []
        for block in self.chain:
            block_height = block.get("index", 0)
            block_hash = block.get("hash", "")
            for tx in block['transactions']:
                tx_info = {
                    "block_height": block_height,
                    "block_hash": block_hash,
                    "tx_hash": tx.get("tx_hash", ""),
                    "from": tx['from'],
                    "to": tx['to'],
                    "amount": tx['amount']
                }
                all_txs.append(tx_info)

        # 如果 user 存在，筛选与其关联的交易
        if user and hasattr(user, "addresses"):
            user_addrs = set(user.addresses)
            user_txs = [
                tx for tx in all_txs
                if tx["from"] in user_addrs or tx["to"] in user_addrs
            ]
            return user_txs

        return all_txs

    def get_last_block(self):
        """
        返回最新区块对象，如果链为空，则返回 None
        """
        self.load_chain()
        if self.chain:
            last_block_data = self.chain[-1]
            transactions = []
            for tx in last_block_data['transactions']:
                transactions.append(Transaction(
                    from_addr=tx['from'],  # 注意这里使用 from_addr
                    to_addr=tx['to'],
                    amount=tx['amount'],
                    signature=tx.get('signature', None)
                ))
            # 将字典转回 Block 对象（便于使用 hash 属性）
            return Block(
                index=last_block_data['index'],
                transactions=transactions,
                previous_hash=last_block_data['previous_hash'],
                timestamp=last_block_data['timestamp']
            )
        return None


bc = Blockchain()
