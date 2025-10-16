import configparser

# ------------------ 配置文件路径 ------------------
CONFIG_FILE = "config.ini"

# ------------------ 加载配置 ------------------
config = configparser.ConfigParser()
config.read(CONFIG_FILE, encoding="utf-8")

# ------------------ 读取默认配置 ------------------
def parse_seed(seed_str: str) -> bytes:
    """把 config 文件里写的 b"..." 或普通字符串转成 bytes"""
    if seed_str.startswith('b"') and seed_str.endswith('"'):
        return seed_str[2:-1].encode("utf-8")
    return seed_str.encode("utf-8")

# Alice 和 Bob 的 seed
SEED_A = parse_seed(config["DEFAULT"].get("SEED_A", "alice_default_seed"))
SEED_B = parse_seed(config["DEFAULT"].get("SEED_B", "bob_default_seed"))

# 最大地址集长度
MAX_ADDR_LENGTH = config["DEFAULT"].getint("MAX_ADDR_LENGTH", 100)

# ------------------ 测试输出 ------------------
if __name__ == "__main__":
    print("SEED_A:", SEED_A)
    print("SEED_B:", SEED_B)
    print("MAX_ADDR_LENGTH:", MAX_ADDR_LENGTH)
