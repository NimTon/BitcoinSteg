from transaction import Transaction
from blockchain import Blockchain

# 模拟账户地址
alice = "AliceAddr"
bob = "BobAddr"

# 创建交易
tx1 = Transaction(alice, bob)
tx2 = Transaction(bob, alice)

# 创建区块链
bc = Blockchain()
if not bc.chain:
    bc.create_genesis_block()
bc.add_block([tx1, tx2])

print("最新区块哈希:", bc.chain[-1].hash)
print("区块交易:", bc.chain[-1].transactions)
