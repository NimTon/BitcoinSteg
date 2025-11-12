import configparser
from utils.utils import parse_seed

# ------------------ 配置文件路径 ------------------
CONFIG_FILE = "config.ini"

# ------------------ 加载配置 ------------------
config = configparser.ConfigParser()
config.read(CONFIG_FILE, encoding="utf-8")

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

# 系统 seed
SYSTEM_PRIVATE_KEY = 'd68d85f5a5f0f159b0c850430b1b839bd6a1f4846dbbda0974ca6b483a8466dc'
SYSTEM_PUBLIC_KEY = '032356ea258204e9600e5fefe4bda4e2f9de3bbdfc3a9d8266d29df508525f4b05'

# 挖矿难度
MINING_DIFFICULTY = config["DEFAULT"].getint("MINING_DIFFICULTY", 4)