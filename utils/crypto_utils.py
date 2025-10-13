import json
import os
import hashlib
from ecdsa import SigningKey, SECP256k1, VerifyingKey

USERS_FILE = 'data/users.json'


def generate_keypair():
    """
    生成密钥对和地址
    返回:
        tuple: (私钥, 公钥, 地址)
    """
    # 生成SECP256k1曲线的私钥
    sk = SigningKey.generate(curve=SECP256k1)
    # 获取对应的公钥
    vk = sk.get_verifying_key()
    # 将私钥转换为十六进制字符串
    private_key = sk.to_string().hex()
    # 将公钥转换为十六进制字符串
    public_key = vk.to_string().hex()
    # 通过公钥生成地址（SHA256哈希的前16位）
    address = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:16]
    return private_key, public_key, address


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
