# utils.py
import hashlib
import secrets
from typing import List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# 可替换为 testnet/mainnet 相关用法
from bitcoinlib.keys import HDKey

# ------------------------
# AES 辅助函数（CBC + PKCS7）
# ------------------------
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    pt_padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pt_padded) + encryptor.finalize()
    return iv + ct

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pt_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(pt_padded) + unpadder.finalize()
    return pt

# ------------------------
# 地址派生（HD）: 从 seed 派生 t 个地址（可指定 network）
# 注意：HDKey.from_seed(seed, network='testnet') 可用于 testnet
# ------------------------
def derive_ordered_addresses(seed_bytes: bytes, t: int, purpose: str = "m/44'/1'/0'/0", network: str = 'testnet') -> List[str]:
    """
    seed_bytes: 任意字节种子（PSK 派生）
    purpose: HD 路径前缀 (不含末尾 index)
    network: 'testnet' or 'bitcoin'
    """
    master = HDKey.from_seed(seed_bytes, network=network)
    addresses = []
    for i in range(t):
        path = f"{purpose}/{i}"
        child = master.subkey_for_path(path)
        addresses.append(child.address())
    return addresses

# ------------------------
# 将 bytes 密文按 le 比特划分成 list of bitstrings
# ------------------------
def split_bytes_to_bitparts(data: bytes, le: int) -> List[str]:
    bit_str = ''.join(f"{byte:08b}" for byte in data)
    parts = [bit_str[i:i+le] for i in range(0, len(bit_str), le)]
    return parts

# ------------------------
# 将 bitstring 拼回 bytes（不足 8 位的末尾会被补 0，调用端应按加密时的字节对齐处理）
# ------------------------
def bitparts_to_bytes(bit_concat: str) -> bytes:
    # 补齐到字节
    pad_len = (8 - (len(bit_concat) % 8)) % 8
    if pad_len:
        bit_concat = bit_concat + ('0' * pad_len)
    bytes_list = [int(bit_concat[i:i+8], 2) for i in range(0, len(bit_concat), 8)]
    return bytes(bytes_list)

# ------------------------
# 模拟 txid：仅用于开发/测试。真实场景请替换为真实序列化交易的双SHA256(tx_serialized)
# ------------------------
def simulate_txid(sender_addr: str, receiver_addr: str, amount_sats: int, nonce: int) -> bytes:
    data = f"{sender_addr}|{receiver_addr}|{amount_sats}|{nonce}".encode()
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# ------------------------
# 从 txid bytes 获取最低 le bits（返回字符串，例如 '010101'）
# ------------------------
def txid_low_bits(txid_bytes: bytes, le: int) -> str:
    bit_str = ''.join(f"{b:08b}" for b in txid_bytes)
    return bit_str[-le:]
