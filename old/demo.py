import json
import os
import time
import hashlib
import random
from ecdsa import SigningKey, SECP256k1, VerifyingKey


# -----------------------------
# 工具函数
# -----------------------------
def generate_keypair():
    """生成secp256k1私钥、公钥"""
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    private_key = sk.to_string().hex()
    public_key = vk.to_string().hex()
    # 简单生成地址: 公钥的哈希前16位
    address = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:16]
    return private_key, public_key, address


def sign_message(private_key_hex, message):
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    signature = sk.sign(message.encode())
    return signature.hex()


def verify_signature(public_key_hex, message, signature_hex):
    vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
    try:
        return vk.verify(bytes.fromhex(signature_hex), message.encode())
    except:
        return False


def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return {}


def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)


# -----------------------------
# 用户系统
# -----------------------------
USERS_FILE = "../data/users.json"


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.wallets = []  # [{'private':..., 'public':..., 'address':...}]

    def add_wallet(self):
        private, public, address = generate_keypair()
        self.wallets.append({'private': private, 'public': public, 'address': address})
        return address

    def get_balance(self, blockchain):
        balance = 0
        for wallet in self.wallets:
            addr = wallet['address']
            balance += blockchain.get_balance(addr)
        return balance


# -----------------------------
# 区块链系统
# -----------------------------
BLOCKCHAIN_FILE = "../data/blockchain.json"


class Transaction:
    def __init__(self, from_addr, to_addr, amount, signature):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            'from': self.from_addr,
            'to': self.to_addr,
            'amount': self.amount,
            'signature': self.signature
        }


class Block:
    def __init__(self, index, transactions, previous_hash, timestamp=None):
        self.index = index
        self.transactions = [tx.to_dict() for tx in transactions]
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

    def load_chain(self):
        data = load_json(BLOCKCHAIN_FILE)
        if data:
            self.chain = data
        else:
            # 创世区块
            genesis = Block(0, [], "0")
            self.chain.append(genesis.__dict__)
            self.save_chain()

    def save_chain(self):
        save_json(BLOCKCHAIN_FILE, self.chain)

    def add_block(self, transactions):
        prev_hash = self.chain[-1]['hash']
        block = Block(len(self.chain), transactions, prev_hash)
        self.chain.append(block.__dict__)
        self.save_chain()

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block['transactions']:
                if tx['from'] == address:
                    balance -= tx['amount']
                if tx['to'] == address:
                    balance += tx['amount']
        return balance


# -----------------------------
# 系统管理
# -----------------------------
class CryptoSystem:
    def __init__(self):
        self.users = load_json(USERS_FILE)
        self.blockchain = Blockchain()

    def register_user(self, username, password):
        if username in self.users:
            return False, "用户名已存在"
        user = User(username, password)
        # 默认生成一个钱包
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
        # 检查余额
        balance = self.blockchain.get_balance(from_addr)
        if amount > balance:
            return False, "余额不足"
        # 找到钱包私钥签名
        wallet = next((w for w in from_user.wallets if w['address'] == from_addr), None)
        if not wallet:
            return False, "钱包不存在"
        signature = sign_message(wallet['private'], f"{from_addr}->{to_addr}:{amount}")
        tx = Transaction(from_addr, to_addr, amount, signature)
        self.blockchain.add_block([tx])
        return True, "交易成功"


# -----------------------------
# 水龙头函数：发币给指定地址
# -----------------------------
def faucet(blockchain, address, amount=50):
    """
    给指定地址发放初始币，用于测试
    """
    tx = Transaction(
        from_addr="SYSTEM",  # 系统发币
        to_addr=address,
        amount=amount,
        signature="SYSTEM"  # 系统交易无需签名
    )
    blockchain.add_block([tx])
    print(f"{amount} 币已发放到 {address}")


# -----------------------------
# 测试
# -----------------------------
if __name__ == "__main__":
    system = CryptoSystem()

    # 注册用户
    system.register_user("alice", "123456")
    system.register_user("bob", "abcdef")

    # 登录用户
    alice, _ = system.login_user("alice", "123456")
    bob, _ = system.login_user("bob", "abcdef")

    # 打印钱包地址
    print("Alice wallets:", [w['address'] for w in alice.wallets])
    print("Bob wallets:", [w['address'] for w in bob.wallets])

    # 给 Alice 和 Bob 发币
    faucet(system.blockchain, alice.wallets[0]['address'], 100)
    faucet(system.blockchain, bob.wallets[0]['address'], 50)

    # 查看余额
    print("Alice balance:", alice.get_balance(system.blockchain))
    print("Bob balance:", bob.get_balance(system.blockchain))

    # Alice 给 Bob 转账 10
    from_addr = alice.wallets[0]['address']
    to_addr = bob.wallets[0]['address']
    success, msg = system.transfer(alice, from_addr, to_addr, 10)
    print(success, msg)

    # 打印余额
    print("Alice balance:", alice.get_balance(system.blockchain))
    print("Bob balance:", bob.get_balance(system.blockchain))
