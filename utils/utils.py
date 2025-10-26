import json
import os


def hex_to_bits(hex_hash: str) -> str:
    """
    将十六进制哈希字符串转换为256位二进制比特串
    例如:
        'a12ce580ec55fd5d...' -> '1010000100101100...'
    """
    # 去除前缀和空格，确保干净
    hex_hash = hex_hash.strip().lower().replace("0x", "")
    # 转为整数后转二进制，并补齐 256 位
    bits = bin(int(hex_hash, 16))[2:].zfill(256)
    return bits


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


def parse_seed(seed_str: str) -> bytes:
    """把 config 文件里写的 b"..." 或普通字符串转成 bytes"""
    if seed_str.startswith('b"') and seed_str.endswith('"'):
        return seed_str[2:-1].encode("utf-8")
    return seed_str.encode("utf-8")


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt'}
