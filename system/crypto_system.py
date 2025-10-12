from utils.crypto_utils import load_json, save_json, sign_message
from users.user import User
from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction

USERS_FILE = "data/users.json"

class CryptoSystem:
    def __init__(self):
        self.users = load_json(USERS_FILE)
        self.blockchain = Blockchain()

    def register_user(self, username, password):
        if username in self.users:
            return False, "用户名已存在"
        user = User(username, password)
        user.add_wallet()
        self.users[username] = {'password': password, 'wallets': user.wallets}
        save_json(USERS_FILE, self.users)
        return True, "注册成功"

    def login_user(self, username, password):
        if username not in self.users:
            return None, "用户不存在"
        if self.users[username]['password'] != password:
            return None, "密码错误"
        user = User(username, password)
        user.wallets = self.users[username]['wallets']
        return user, "登录成功"

    def transfer(self, from_user: User, from_addr, to_addr, amount):
        balance = self.blockchain.get_balance(from_addr)
        if amount > balance:
            return False, "余额不足"
        wallet = next((w for w in from_user.wallets if w['address'] == from_addr), None)
        if not wallet:
            return False, "钱包不存在"
        signature = sign_message(wallet['private'], f"{from_addr}->{to_addr}:{amount}")
        tx = Transaction(from_addr, to_addr, amount, signature)
        self.blockchain.add_block([tx])
        return True, "交易成功"
