from system.crypto_system import CryptoSystem
from utils.utils_encrypt_tx import decrypt_from_transactions

# 打印原始消息比特流
system = CryptoSystem()
bob, _ = system.login_user("Bob", "123")
decoded_msg = decrypt_from_transactions(bob)
print(decoded_msg)