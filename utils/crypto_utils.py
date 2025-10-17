import json
import os
import hashlib
from ecdsa import SigningKey, SECP256k1, VerifyingKey
import base58

USERS_FILE = 'data/users.json'


def generate_btc_keypair():
    """
    生成密钥对和地址
    返回:
        tuple: (私钥_hex, 公钥_hex, 地址)
    """
    # 1. 生成 SECP256k1 私钥
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()

    private_key = sk.to_string().hex()
    public_key = vk.to_string("compressed").hex()  # 压缩公钥，更接近比特币实际

    # 2. 生成地址
    # 2.1 对公钥做 SHA256
    sha256_pub = hashlib.sha256(bytes.fromhex(public_key)).digest()
    # 2.2 对 SHA256 的结果做 RIPEMD160
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    hashed_pubkey = ripemd160.digest()
    # 2.3 添加网络字节（0x00 表示主网）
    prefixed_hash = b'\x00' + hashed_pubkey
    # 2.4 计算 checksum（前4字节 SHA256(SHA256(...))）
    checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
    # 2.5 拼接并 Base58 编码
    address_bytes = prefixed_hash + checksum
    address = base58.b58encode(address_bytes).decode()

    return private_key, public_key, address


def generate_btc_keypair_from_seed(seed: bytes):
    """
    由给定种子生成确定性比特币密钥对
    """
    # 对种子进行一次哈希，得到确定性私钥
    private_key_bytes = hashlib.sha256(seed).digest()
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()

    private_key = sk.to_string().hex()
    public_key = vk.to_string("compressed").hex()

    # 生成比特币地址
    sha256_pub = hashlib.sha256(bytes.fromhex(public_key)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    hashed_pubkey = ripemd160.digest()
    prefixed_hash = b'\x00' + hashed_pubkey
    checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
    address_bytes = prefixed_hash + checksum
    address = base58.b58encode(address_bytes).decode()

    return private_key, public_key, address


def generate_btc_keypairs_from_seed(seed: bytes, count: int):
    """
    由给定种子生成 count 个确定性比特币密钥对（主+子）
    - 第一个为主密钥
    - 后续 count-1 个为子密钥
    """
    keypairs = []

    # --- 生成主密钥 ---
    private_key_bytes = hashlib.sha256(seed).digest()
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()

    private_key = sk.to_string().hex()
    public_key = vk.to_string("compressed").hex()

    sha256_pub = hashlib.sha256(bytes.fromhex(public_key)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    hashed_pubkey = ripemd160.digest()
    prefixed_hash = b'\x00' + hashed_pubkey
    checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
    address_bytes = prefixed_hash + checksum
    address = base58.b58encode(address_bytes).decode()

    keypairs.append((private_key, public_key, address))

    # --- 生成子密钥 ---
    for i in range(1, count):  # 从1开始，确保主+子 = count
        print("Generating subkey:", i)
        derived_seed = hashlib.sha256(seed + i.to_bytes(4, 'big')).digest()
        sk = SigningKey.from_string(derived_seed, curve=SECP256k1)
        vk = sk.get_verifying_key()

        private_key = sk.to_string().hex()
        public_key = vk.to_string("compressed").hex()

        sha256_pub = hashlib.sha256(bytes.fromhex(public_key)).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_pub)
        hashed_pubkey = ripemd160.digest()
        prefixed_hash = b'\x00' + hashed_pubkey
        checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
        address_bytes = prefixed_hash + checksum
        address = base58.b58encode(address_bytes).decode()

        keypairs.append((private_key, public_key, address))

    return keypairs


def sign_message(private_key_hex, message):
    """
    使用私钥对消息进行签名
    参数:
        private_key_hex (str): 私钥的十六进制字符串
        message (str): 需要签名的消息
    返回:
        str: 签名的十六进制字符串
    """
    # 从十六进制字符串恢复私钥
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    # 对消息进行签名
    signature = sk.sign(message.encode())
    # 将签名转换为十六进制字符串返回
    return signature.hex()


def verify_signature(public_key_hex, message, signature_hex):
    """
    验证消息签名是否有效
    参数:
        public_key_hex (str): 公钥的十六进制字符串
        message (str): 原始消息
        signature_hex (str): 签名的十六进制字符串
    返回:
        bool: 签名验证结果，True表示有效，False表示无效
    """
    # 从十六进制字符串恢复公钥
    vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
    try:
        # 验证签名
        return vk.verify(bytes.fromhex(signature_hex), message.encode())
    except:
        # 验证失败返回False
        return False


def load_json(file_path):
    """
    从文件加载JSON数据
    参数:
        file_path (str): JSON文件路径
    返回:
        dict: 加载的JSON数据，如果文件不存在则返回空字典
    """
    # 检查文件是否存在
    if os.path.exists(file_path):
        # 读取并解析JSON文件
        with open(file_path, "r") as f:
            return json.load(f)
    return {}


def save_json(file_path, data):
    """
    将数据保存为JSON文件
    参数:
        file_path (str): 保存的文件路径
        data (dict): 需要保存的数据
    """
    # 写入JSON文件，使用2个空格缩进
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)


def get_public_key_from_address(address):
    """
    根据钱包地址查找公钥
    :param address: 钱包地址
    :return: 公钥字符串或 None
    """
    users = load_json(USERS_FILE)
    for user in users.values():
        for wallet in user.get("wallets", []):
            if wallet.get("address") == address:
                return wallet.get("public")
    return None
