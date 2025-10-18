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

# 明文消息
MESSAGE = config["DEFAULT"].get("MESSAGE", "Hello, World!")

# 匹配位数
MATCH_BITS = config["DEFAULT"].getint("MATCH_BITS", 8)

# 消息终止符
END_MARKER = config["DEFAULT"].get("END_MARKER", "<END_OF_MESSAGE>")
