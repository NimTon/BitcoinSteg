# 用户A和用户B
from wallet import Wallet  # 假设我们上面定义的 Wallet 类在 wallet.py

wallet_A = Wallet()
wallet_B = Wallet()

print("A地址:", wallet_A.address)
print("B地址:", wallet_B.address)

from transaction import Transaction

amount = 50  # 转账数量

# 创建交易
tx = Transaction(
    sender_address=wallet_A.address,
    receiver_address=wallet_B.address,
    amount=amount
)

# 使用私钥对交易哈希签名
tx.signature = wallet_A.sign(tx.hash)

print("交易哈希:", tx.hash)
print("签名:", tx.signature)

# 用发送方的公钥验证签名
valid = wallet_A.verify(tx.hash, tx.signature)
print("签名有效:", valid)

from blockchain import Blockchain

blockchain = Blockchain()  # 会自动加载或创建创世块
blockchain.add_block([tx])  # 将交易放到新区块


for block in blockchain.chain:
    for t in block.transactions:
        if t.receiver == wallet_B.address:
            print("B收到交易:", t.amount, "来自:", t.sender)
