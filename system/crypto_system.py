from utils.utils_crypto import sign_message
from users.user import User
from blockchain import blockchain
from blockchain.transaction import Transaction

class CryptoSystem:
    """
    加密货币系统主类
    管理用户注册、登录、钱包操作和交易功能
    """

    def __init__(self):
        # 初始化区块链
        self.blockchain = blockchain

    # ===============================
    # 用户注册 / 登录
    # ===============================

    def register_user(self, username, password, create_default_wallet: bool = True):
        """注册新用户"""
        if User.load(username):
            return False, "用户名已存在"

        user = User(username, password)
        if create_default_wallet:
            user.add_wallet()
        user.save()
        return True, "注册成功"

    def login_user(self, username, password):
        """用户登录"""
        user = User.load(username, password)
        if not user:
            return None, "登录失败"
        return user, "登录成功"

    # ===============================
    # 钱包管理功能（增、删、查）
    # ===============================

    def add_wallet(self, user: User):
        """为用户新增一个钱包"""
        new_address = user.add_wallet()
        user.save()
        return True, "新增钱包成功", new_address

    def add_custom_wallet(self, user: User, private_key, public_key, address):
        """为用户添加自定义钱包"""
        if not private_key or not public_key or not address:
            return False, "私钥、公钥或地址不能为空", None

        # 检查地址是否重复
        for w in user.wallets:
            if w['address'] == address:
                return False, "地址已存在", None

        user.wallets.append({
            "private": private_key,
            "public": public_key,
            "address": address
        })
        user.save()
        return True, "自定义钱包添加成功", address

    def delete_wallet(self, user: User, address):
        """删除用户钱包（余额为0才允许）"""
        target = next((w for w in user.wallets if w['address'] == address), None)
        if not target:
            return False, "钱包不存在"

        balance = self.blockchain.get_balance(address)
        if balance > 0:
            return False, "钱包余额非零，无法删除"

        user.wallets.remove(target)
        user.save()
        return True, "删除钱包成功"

    def list_wallets(self, user: User):
        """查询用户所有钱包及余额"""
        result = []
        for w in user.wallets:
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

        signature = sign_message(wallet['private'], f"{from_addr}->{to_addr}:{amount}")
        tx = Transaction(from_addr, to_addr, amount, signature)
        block = self.blockchain.add_block([tx], timestamp)
        return True, "交易成功", tx.hash, block.hash
