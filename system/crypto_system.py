from utils.crypto_utils import load_json, save_json, sign_message
from users.user import User
from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction

# 用户数据存储文件路径
USERS_FILE = "data/users.json"


class CryptoSystem:
    """
    加密货币系统主类
    管理用户注册、登录和交易等功能
    """

    def __init__(self):
        # 从文件加载用户数据
        self.users = load_json(USERS_FILE)
        # 初始化区块链
        self.blockchain = Blockchain()

    def register_user(self, username, password):
        """
        注册新用户
        :param username: 用户名
        :param password: 密码
        :return: (bool, str) 注册结果和消息
        """
        # 检查用户名是否已存在
        if username in self.users:
            return False, "用户名已存在"
        # 创建新用户并添加钱包
        user = User(username, password)
        user.add_wallet()
        # 保存用户信息到内存和文件
        self.users[username] = {'password': password, 'wallets': user.wallets}
        save_json(USERS_FILE, self.users)
        return True, "注册成功"

    def login_user(self, username, password):
        """
        用户登录
        :param username: 用户名
        :param password: 密码
        :return: (User/None, str) 用户对象和登录消息
        """
        # 检查用户是否存在
        if username not in self.users:
            return None, "用户不存在"
        # 验证密码
        if self.users[username]['password'] != password:
            return None, "密码错误"
        # 创建用户对象并加载钱包信息
        user = User(username, password)
        user.wallets = self.users[username]['wallets']
        return user, "登录成功"

    def transfer(self, from_user: User, from_addr, to_addr, amount):
        """
        执行转账交易
        :param from_user: 发送方用户对象
        :param from_addr: 发送方钱包地址
        :param to_addr: 接收方钱包地址
        :param amount: 转账金额
        :return: (bool, str, str) 交易结果、消息和交易哈希
        """
        # 检查发送方余额是否足够
        balance = self.blockchain.get_balance(from_addr)
        if amount > balance:
            return False, "余额不足", None
        # 查找发送方钱包
        wallet = next((w for w in from_user.wallets if w['address'] == from_addr), None)
        if not wallet:
            return False, "钱包不存在", None
        # 对交易信息进行签名
        signature = sign_message(wallet['private'], f"{from_addr}->{to_addr}:{amount}")
        # 创建交易并添加到区块链
        tx = Transaction(from_addr, to_addr, amount, signature)
        self.blockchain.add_block([tx])
        return True, "交易成功", tx.hash

    def save_users(self):
        """
        保存内存中的用户数据到文件
        """
        save_json(USERS_FILE, self.users)
