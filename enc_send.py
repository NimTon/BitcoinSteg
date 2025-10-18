import os
import time
from blockchain.blockchain import bc
from config import SEED_A, MAX_ADDR_LENGTH, SEED_B, MESSAGE
from utils.utils_crypto import generate_btc_keypairs_from_seed

# ------------------ 初始化环境 ------------------
for f in ["data/blockchain.json", "data/users.json"]:
    try:
        os.remove(f)
    except FileNotFoundError:
        pass
time.sleep(0.1)

from system.crypto_system import CryptoSystem
from utils.utils_encrypt_tx import encrypt_and_send

# ------------------ 初始化系统 ------------------
print("初始化加密系统...")
system = CryptoSystem()

# 注册用户
print("注册用户 Alice 和 Bob...")
system.register_user("Alice", "123", False)
system.register_user("Bob", "123", False)

# 登录用户
print("用户登录...")
alice, _ = system.login_user("Alice", "123")
bob, _ = system.login_user("Bob", "123")

# # ------------------ 生成钱包地址 ------------------
print("为 Alice 和 Bob 生成钱包地址...")
# Alice 根据 seed 生成 N 个地址
alice.wallets = generate_btc_keypairs_from_seed(SEED_A, MAX_ADDR_LENGTH)
# Bob 只生成一个地址作为接收地址
bob.wallets = generate_btc_keypairs_from_seed(SEED_B, 1)

# ------------------ 将私钥、公钥、地址加入系统钱包 ------------------
print("添加钱包到系统并注入测试资金...")
for i, wallet in enumerate(alice.wallets):
    private_key, public_key, address = wallet
    system.add_custom_wallet(alice.username, private_key, public_key, address)
    bc.faucet(address, 1000)
    print(f"Alice 钱包 {i + 1} 已添加: {address}")

for i, wallet in enumerate(bob.wallets):
    private_key, public_key, address = wallet
    system.add_custom_wallet(bob.username, private_key, public_key, address)
    bc.faucet(address, 1000)
    print(f"Bob 钱包 {i + 1} 已添加: {address}")

print(f"\n准备发送消息: {MESSAGE}")
print("开始加密并发送交易...")

encrypt_and_send(system, from_user=alice, message=MESSAGE)
print("完成！")