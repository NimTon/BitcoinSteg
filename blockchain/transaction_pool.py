from utils.utils import load_json, save_json

# 交易池文件路径
TX_POOL_FILE = "data/transaction_pool.json"


class TransactionPool:
    def __init__(self, file_path=TX_POOL_FILE):
        self.file_path = file_path
        self.pool = []
        self.load_pool()

    def load_pool(self):
        """从文件加载交易池"""
        data = load_json(self.file_path)
        if data:
            self.pool = data
        else:
            self.pool = []

    def save_pool(self):
        """保存交易池到文件"""
        save_json(self.file_path, self.pool)

    def add_transaction(self, tx):
        """向交易池添加交易"""
        self.load_pool()
        if not hasattr(tx, "to_dict"):
            raise TypeError("交易对象无效，必须是 Transaction 类型")
        self.pool.append(tx.to_dict())
        self.save_pool()

    def remove_transaction(self, tx_hash):
        """根据交易哈希移除交易"""
        self.load_pool()
        self.pool = [tx for tx in self.pool if tx.get("hash") != tx_hash]
        self.save_pool()

    def get_transactions_for_block(self, max_count=None):
        """
        获取交易池中的交易，用于打包区块
        可选限制数量
        """
        self.load_pool()
        # 默认按照加入顺序，可扩展按手续费排序
        if max_count is not None:
            return self.pool[:max_count]
        return self.pool.copy()

    def clear_pool(self):
        """清空交易池"""
        self.pool = []
        self.save_pool()

    def get_all_transactions(self):
        """获取交易池中所有交易"""
        self.load_pool()
        return self.pool.copy()
