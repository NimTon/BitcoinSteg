from decimal import Decimal, getcontext

from utils.utils_crypto import generate_btc_keypair

# 设置精度，确保至少到 1e-8
getcontext().prec = 16


class User:
    """
    用户类，用于管理用户信息和钱包
    """

    def __init__(self, username, password):
        """
        初始化用户对象
        
        Args:
            username (str): 用户名
            password (str): 密码
        """
        self.username = username
        self.password = password
        self.wallets = []  # 钱包列表，每个元素包含私钥、公钥和地址

    def add_wallet(self):
        """
        为用户添加一个新的钱包
        
        Returns:
            str: 新生成的钱包地址
        """
        # 生成密钥对和地址
        private, public, address = generate_btc_keypair()
        # 将钱包信息添加到用户的钱包列表中
        self.wallets.append({'private': private, 'public': public, 'address': address})
        return address

    def get_balance(self, blockchain):
        """
        获取用户所有钱包的总余额（高精度）
        """
        balance = Decimal('0')
        for wallet in self.wallets:
            addr = wallet['address']
            # 用 Decimal 包装 blockchain.get_balance 输出
            balance += Decimal(str(blockchain.get_balance(addr)))
        return balance
