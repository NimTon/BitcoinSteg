import hashlib
from ecdsa import SigningKey, SECP256k1
import base58


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
    # signature = sk.sign(message.encode())
    signature = sk.sign_deterministic(message.encode())  # 确定性签名
    # 将签名转换为十六进制字符串返回
    return signature.hex()
