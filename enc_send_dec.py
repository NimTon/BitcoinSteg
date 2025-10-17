from system.crypto_system import CryptoSystem
from utils.crypto_utils import generate_btc_keypairs_from_seed, sign_message, verify_signature
from blockchain.blockchain import bc
from config import SEED_A, SEED_B, MAX_ADDR_LENGTH, CHUNK_SIZE

system = CryptoSystem()

# 注册用户
system.register_user("Alice", "123", False)
system.register_user("Bob", "123", False)

# 登录用户
alice, _ = system.login_user("Alice", "123")
bob, _ = system.login_user("Bob", "123")

# ------------------ 生成钱包地址 ------------------
# Alice 根据 seed 生成 N 个地址
alice.wallets = generate_btc_keypairs_from_seed(SEED_A, MAX_ADDR_LENGTH)
# Bob 只生成一个地址作为接收地址
bob.wallets = generate_btc_keypairs_from_seed(SEED_B, 1)

# ------------------ 将私钥、公钥、地址加入钱包 ------------------
for wallet in alice.wallets:
    private_key = wallet[0]
    public_key = wallet[1]
    address = wallet[2]
    system.add_custom_wallet(alice.username, private_key, public_key, address)
for wallet in bob.wallets:
    private_key = wallet[0]
    public_key = wallet[1]
    address = wallet[2]
    system.add_custom_wallet(bob.username, private_key, public_key, address)

# ------------------ Alice 发送加密内容 ------------------
def encrypt_and_send(alice, bob, message):
    """
    Alice 根据加密内容选择交易额进行交易，模拟发送到 Bob
    """
    # 将消息切分成短序列，每个序列对应一个交易
    msg_bytes = message.encode()
    chunks = [msg_bytes[i:i + CHUNK_SIZE] for i in range(0, len(msg_bytes), CHUNK_SIZE)]
    print(chunks)
    exit()

    # 模拟交易
    transactions = []
    for i, chunk in enumerate(chunks):
        from_wallet = alice.wallets[i % len(alice.wallets)]
        to_wallet = bob.wallets[0]  # 发送到 Bob 的接收地址
        # 选择交易额 = sum(byte值)/10 (伪逻辑)
        amount = sum(chunk) / 10
        # 用 Alice 私钥签名 chunk（模拟）
        signature = sign_message(from_wallet[0], chunk.hex())
        tx = {
            "from": from_wallet[2],
            "to": to_wallet[2],
            "amount": amount,
            "chunk": chunk.hex(),
            "signature": signature
        }
        transactions.append(tx)
    return transactions


# 模拟发送
message = "Hello Bob, this is secret message via blockchain addresses."
transactions = encrypt_and_send(alice, bob, message)


# ------------------ Bob 接收并解密 ------------------
def receive_and_decrypt(bob, transactions):
    """
    Bob 根据 seed 生成地址集顺序，拼接 chunk 解密消息
    """
    # 生成与 Alice 对应的有序地址集（假设已共享 seed 和顺序）
    bob_addresses = [bob.wallets[0][2]]  # 这里只有一个接收地址
    # 按顺序拼接交易 chunk
    collected_bytes = b""
    for tx in transactions:
        if tx["to"] in bob_addresses:
            collected_bytes += bytes.fromhex(tx["chunk"])
    # 解密/还原消息（这里直接拼接）
    return collected_bytes.decode()


# 接收消息
received_message = receive_and_decrypt(bob, transactions)
print("Bob 收到的消息:", received_message)

# ------------------ 输出 Alice 和 Bob 钱包信息 ------------------
print("Alice wallets:", [w[2] for w in alice.wallets])
print("Bob wallet:", bob.wallets[0][2])

# 输出交易记录
for tx in transactions:
    print(tx)
