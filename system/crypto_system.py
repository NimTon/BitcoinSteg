from utils.utils_crypto import load_json, save_json, sign_message
from users.user import User
from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction

# 用户数据存储文件路径
USERS_FILE = "data/users.json"


class CryptoSystem:
    """
    加密货币系统主类
    管理用户注册、登录、钱包操作和交易功能
    """

    def __init__(self):
        # 从文件加载用户数据
        self.users = load_json(USERS_FILE)
        # 初始化区块链
        self.blockchain = Blockchain()

    # ===============================
    # 用户注册 / 登录
    # ===============================

    def register_user(self, username, password, create_default_wallet: bool = True):
        """注册新用户"""
        if username in self.users:
            return False, "用户名已存在"

        user = User(username, password)
        if create_default_wallet:
            user.add_wallet()
        self.users[username] = {'password': password, 'wallets': user.wallets}
        save_json(USERS_FILE, self.users)
        return True, "注册成功"

    def login_user(self, username, password):
        """用户登录"""
        if username not in self.users:
            return None, "用户不存在"
        if self.users[username]['password'] != password:
            return None, "密码错误"

        user = User(username, password)
        user.wallets = self.users[username]['wallets']
        return user, "登录成功"

    # ===============================
    # 钱包管理功能（增、删、查）
    # ===============================

    def add_wallet(self, username):
        """
        为用户新增一个钱包
        :param username: 用户名
        :return: (bool, str, dict) 成功标志, 消息, 新钱包信息
        """
        if username not in self.users:
            return False, "用户不存在", None

        user = User(username, self.users[username]['password'])
        user.wallets = self.users[username]['wallets']

        new_wallet = user.add_wallet()
        self.users[username]['wallets'] = user.wallets
        save_json(USERS_FILE, self.users)
        return True, "新增钱包成功", new_wallet

    def add_custom_wallet(self, username, private_key, public_key, address):
        """
        为用户添加一个指定密钥对和地址的钱包
        :param username: 用户名
        :param private_key: 私钥（hex字符串）
        :param public_key: 公钥（hex字符串）
        :param address: 地址（Base58字符串）
        :return: (bool, str, dict) 成功标志, 消息, 新钱包信息
        """
        if username not in self.users:
            return False, "用户不存在", None

        # 校验参数合法性（可选）
        if not private_key or not public_key or not address:
            return False, "私钥、公钥或地址不能为空", None

        # 检查地址是否重复
        for wallet in self.users[username]['wallets']:
            if wallet['address'] == address:
                return False, "地址已存在", None

        # 添加自定义钱包
        new_wallet = {
            "private": private_key,
            "public": public_key,
            "address": address
        }

        self.users[username]['wallets'].append(new_wallet)
        save_json(USERS_FILE, self.users)
        return True, "自定义钱包添加成功", new_wallet

    def delete_wallet(self, username, address):
        """
        删除用户的钱包（仅当余额为0时允许删除）
        :param username: 用户名
        :param address: 钱包地址
        :return: (bool, str)
        """
        if username not in self.users:
            return False, "用户不存在"

        wallets = self.users[username]['wallets']
        target = next((w for w in wallets if w['address'] == address), None)
        if not target:
            return False, "钱包不存在"

        # 检查余额
        balance = self.blockchain.get_balance(address)
        if balance > 0:
            return False, "钱包余额非零，无法删除"

        # 删除钱包
        wallets.remove(target)
        save_json(USERS_FILE, self.users)
        return True, "删除钱包成功"

    def list_wallets(self, username):
        """
        查询用户的所有钱包信息（包括余额）
        :param username: 用户名
        :return: (bool, str, list)
        """
        if username not in self.users:
            return False, "用户不存在", []

        wallets = self.users[username]['wallets']
        result = []
        for w in wallets:
            balance = self.blockchain.get_balance(w['address'])
            result.append({
                "address": w['address'],
                "public": w['public'],
                "balance": balance
            })

        return True, "查询成功", result

    # ===============================
    # 交易逻辑
    # ===============================

    def transfer(self, from_user: User, from_addr, to_addr, amount, timestamp=None):
        """执行转账交易"""
        balance = self.blockchain.get_balance(from_addr)
        if amount > balance:
            return False, "余额不足", None, None

        wallet = next((w for w in from_user.wallets if w['address'] == from_addr), None)
        if not wallet:
            return False, "钱包不存在", None, None

        # 签名交易信息
        signature = sign_message(wallet['private'], f"{from_addr}->{to_addr}:{amount}")

        # 创建交易并上链
        tx = Transaction(from_addr, to_addr, amount, signature)
        block = self.blockchain.add_block([tx], timestamp)
        return True, "交易成功", tx.hash, block.hash

    # ===============================
    # 数据持久化
    # ===============================

    def save_users(self):
        """保存用户数据"""
        save_json(USERS_FILE, self.users)
