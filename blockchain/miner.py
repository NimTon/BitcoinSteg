from blockchain.block import Block
from blockchain.transaction import Transaction
from utils.utils_crypto import sign_message
from config import SYSTEM_PRIVATE_KEY
from blockchain import Blockchain, TransactionPool


class Miner:
    def __init__(self, blockchain: Blockchain, tx_pool: TransactionPool, miner_address: str):
        """
        初始化矿工对象
        :param blockchain: Blockchain 对象
        :param tx_pool: TransactionPool 对象
        :param miner_address: 矿工地址（用于奖励）
        """
        self.blockchain = blockchain
        self.tx_pool = tx_pool
        self.miner_address = miner_address

    def mine(self, max_txs_per_block=None, reward=1, difficulty=1, max_attempts=None):
        """
        挖矿：从交易池拿交易打包新区块，发放奖励
        :param max_txs_per_block: 每个区块最多打包交易数
        :param reward: 系统奖励数量
        :param difficulty: PoW 难度（前缀0数量）
        :param max_attempts: PoW最大尝试次数
        :return: 新挖出的 Block 对象
        """
        # 1. 从交易池取交易
        txs_to_pack = self.tx_pool.get_transactions_for_block(max_txs_per_block)
        if not txs_to_pack:
            raise Exception("交易池中没有交易")

        # 2. 创建 CoinBase 交易（系统奖励）
        block_index = len(self.blockchain.chain)
        message = f"{self.miner_address}:{reward}:{block_index}"
        signature = sign_message(SYSTEM_PRIVATE_KEY, message)
        coinbase_tx = Transaction("SYSTEM", self.miner_address, reward, signature)

        # 3. 构造区块交易列表：奖励交易放在最前面
        all_txs = [coinbase_tx] + [
            Transaction(
                from_addr=tx.get("from"),
                to_addr=tx.get("to"),
                amount=tx.get("amount"),
                signature=tx.get("signature"),
                op_return=tx.get("op_return")
            ) if isinstance(tx, dict) else tx
            for tx in txs_to_pack
        ]
        # 4. 获取前一区块哈希
        prev_hash = self.blockchain.chain[-1]['hash']

        # 5. 创建新区块
        block = Block(len(self.blockchain.chain), all_txs, prev_hash)

        # 6. 挖矿 PoW
        mined_hash = block.mine(difficulty=difficulty, max_attempts=max_attempts)

        # 7. 将区块加入区块链
        self.blockchain.chain.append(block.__dict__)
        self.blockchain.save_chain()

        # 8. 从交易池移除已打包交易
        for tx in txs_to_pack:
            self.tx_pool.remove_transaction(tx.get("hash"))

        return True
