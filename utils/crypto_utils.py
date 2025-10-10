import hashlib, random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ========== AES 加解密 ==========
def aes_encrypt(message: str, key: bytes) -> str:
    cipher = AES.new(pad(key, 16), AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode(), 16))
    return ciphertext.hex()

def aes_decrypt(cipher_hex: str, key: bytes) -> str:
    cipher = AES.new(pad(key, 16), AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(bytes.fromhex(cipher_hex)), 16)
    return decrypted.decode(errors="ignore")

# ========== ECC 密钥拓展算法 ==========
def key_expand(sk_init: int, AES_KEY: bytes, n: int) -> int:
    h = hashlib.sha256(AES_KEY + str(sk_init).encode()).hexdigest()
    new_sk = int(h, 16) % n
    return new_sk

# ========== 交易哈希计算 ==========
def tx_hash(sender_addr: str, receiver_addr: str, amount: int) -> str:
    data = f"{sender_addr}{receiver_addr}{amount:016x}"
    return hashlib.sha256(data.encode()).hexdigest()

# ========== 子密文提取 ==========
def extract_lsb_bits(hex_str: str, le: int) -> str:
    binary = bin(int(hex_str, 16))[2:].zfill(256)
    return binary[-le:]

# ========== 金额随机采样 ==========
def random_amount():
    return random.randint(1, 1000)

# ========== 终止符检测 ==========
def has_terminator(bits: str, terminator: str) -> bool:
    return bits.endswith(terminator)

# ========== 系统参数 ==========
CONFIG = {
    "a": 82,
    "b": 169,
    "p": 25003,
    "G": (0, 13),
    "n": 1797,
    "AES_KEY": b"197",
    "TERMINATOR": "011111110",
    "LE": 6,
}
