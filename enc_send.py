import os
import time

# ------------------ 初始化环境 ------------------
# for f in ["data/blockchain.json", "data/users.json"]:
#     try:
#         os.remove(f)
#     except FileNotFoundError:
#         pass
# time.sleep(0.1)

from config import MESSAGE
from system.crypto_system import CryptoSystem
from utils.utils_encrypt_tx import encrypt_and_send, init_seed_a_wallets, init_seed_b_wallets

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

# 初始化钱包
print("初始化钱包...")
# init_seed_a_wallets(system, alice)
# init_seed_b_wallets(system, bob)


MESSAGE = "这是另一个测试"
print(f"\n准备发送消息: {MESSAGE}")

encrypt_and_send(system, from_user=alice, message=MESSAGE)
print("完成！")
