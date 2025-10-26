from decimal import Decimal, getcontext
from utils.utils_crypto import generate_btc_keypair
from utils.utils import load_json, save_json

# 设置精度，确保至少到 1e-8
getcontext().prec = 16

USERS_FILE = "data/users.json"


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
        private, public, address = generate_btc_keypair()
        self.wallets.append({'private': private, 'public': public, 'address': address})
        return address

    def get_balance(self, blockchain):
        """
        获取用户所有钱包的总余额（高精度）
        """
        balance = Decimal('0')
        for wallet in self.wallets:
            addr = wallet['address']
            balance += Decimal(str(blockchain.get_balance(addr)))
        return balance

    def to_dict(self):
        """
        转换用户对象为字典，方便保存到文件
        """
        return {
            'username': self.username,
            'password': self.password,
            'wallets': self.wallets
        }

    def save(self):
        """
        保存当前用户到 USERS_FILE。
        如果文件存在，先读取原有用户数据，更新/添加当前用户。
        """
        data = load_json(USERS_FILE) or {}
        data[self.username] = self.to_dict()
        save_json(USERS_FILE, data)

    @classmethod
    def load(cls, username, password=None):
        """
        从文件加载指定用户名的用户对象
        """
        data = load_json(USERS_FILE) or {}
        usernames = data.keys()
        if username not in usernames:
            return None
        user = data[username]
        if password and user['password'] != password:
            return None
        obj = cls(username, user['password'])
        obj.wallets = user.get('wallets', [])
        return obj

    @classmethod
    def load_all(cls):
        """
        加载所有用户，返回 User 对象列表
        """
        data = load_json(USERS_FILE) or {}
        return data
