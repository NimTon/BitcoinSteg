import hashlib
import json
import time
from blockchain.transaction import Transaction
from blockchain.blockchain import bc
from utils.utils_crypto import sign_message, generate_btc_keypairs_from_seed
from typing import List
from config import SEED_A, SEED_B, MESSAGE, MATCH_BITS, END_MARKER, MAX_ADDR_LENGTH


def init_seed_a_wallets(system, user):
    """
    初始化 SEED_A 地址集 (发送方钱包)
    - 为用户创建 MAX_ADDR_LENGTH 个钱包
    - 每个钱包注入 1000 单位资金
    """
    wallets = generate_btc_keypairs_from_seed(SEED_A, MAX_ADDR_LENGTH)
    for i, (priv, pub, addr) in enumerate(wallets, start=1):
        created, _, _ = system.add_custom_wallet(user.username, priv, pub, addr)
        if created:
            bc.faucet(addr, 1000)
        # print(f"[A{i:03d}] 初始化 SEED_A 钱包: {addr} 并注入 1000 资金")
    print(f"[✓] SEED_A 钱包初始化完成，共 {len(wallets)} 个。")
    return wallets


def init_seed_b_wallets(system, user):
    """
    初始化 SEED_B 地址集 (接收方钱包)
    - 为用户创建 MAX_ADDR_LENGTH 个钱包
    - 每个钱包注入 1000 单位资金
    """
    wallets = generate_btc_keypairs_from_seed(SEED_B, MAX_ADDR_LENGTH)
    for i, (priv, pub, addr) in enumerate(wallets, start=1):
        created, _, _ = system.add_custom_wallet(user.username, priv, pub, addr)
        if created:
            bc.faucet(addr, 1000)
        # print(f"[B{i:03d}] 初始化 SEED_B 钱包: {addr} 并注入 1000 资金")
    print(f"[✓] SEED_B 钱包初始化完成，共 {len(wallets)} 个。")
    return wallets


def hex_to_bits(hex_hash: str) -> str:
    """
    将十六进制哈希字符串转换为256位二进制比特串
    例如:
        'a12ce580ec55fd5d...' -> '1010000100101100...'
    """
    # 去除前缀和空格，确保干净
    hex_hash = hex_hash.strip().lower().replace("0x", "")
    # 转为整数后转二进制，并补齐 256 位
    bits = bin(int(hex_hash, 16))[2:].zfill(256)
    return bits


# ------------------ 模拟函数 ------------------
def simulate_block_hash_future_block(from_addr, to_addr, amount, from_privkey_hex,
                                     prev_block_hash='0' * 64, index=0, future_offset=1.0):
    """
    模拟一个交易所在未来时间的区块，并返回 block_hash 及其二进制比特串
    """
    # 签名交易
    message = f"{from_addr}->{to_addr}:{amount}"
    signature_hex = sign_message(from_privkey_hex, message)
    tx = Transaction(from_addr, to_addr, amount, signature_hex)

    # 模拟交易列表
    transactions = [tx]

    # 未来时间戳
    timestamp = time.time() + future_offset

    # 构造区块数据
    block_data = {
        'index': index,
        'transactions': [t.to_dict() for t in transactions],
        'previous_hash': prev_block_hash,
        'timestamp': timestamp,
        'nonce': 0
    }

    # 转成 JSON 并计算 SHA256
    # print('模拟', block_data)
    block_string = json.dumps(block_data, sort_keys=True)
    block_hash_hex = hashlib.sha256(block_string.encode()).hexdigest()
    block_hash_bits = hex_to_bits(block_hash_hex)

    return block_hash_hex, block_hash_bits, timestamp


def send_transaction(tx, system, user, timestamp=None):
    """
    发送一笔交易到区块链系统
    tx: dict, 包含 "from", "to", "amount", "chunk", "signature"
    system: 区块链系统实例，必须有 transfer 方法
    alice: 发起方 User 对象
    """
    from_addr = tx["from"]
    to_addr = tx["to"]
    amount = tx["amount"]

    success, msg, tx_hash, block_hash = system.transfer(user, from_addr, to_addr, amount, timestamp)
    if success:
        print(f"[✓] 交易成功: {from_addr} -> {to_addr} amount={amount}, block_hash={block_hash}")
    else:
        print(f"[✗] 交易失败: {from_addr} -> {to_addr} amount={amount}, 原因: {msg}")

    return success, tx_hash


# ------------------ 主逻辑函数 ------------------
def encrypt_and_send(system, from_user, message=None, max_attempts=1000, step=0.01):
    if not message:
        message = MESSAGE

    # 拼接消息结束符
    full_message = message + END_MARKER
    msg_bytes = full_message.encode("utf-8")
    msg_bits = ''.join(format(b, '08b') for b in msg_bytes)
    print(f"[i] 原始消息比特流 ({len(msg_bits)} bits):\n{msg_bits}")

    # 切分为固定比特块
    chunks_bits = [msg_bits[i:i + MATCH_BITS] for i in range(0, len(msg_bits), MATCH_BITS)]
    if len(chunks_bits[-1]) < MATCH_BITS:
        chunks_bits[-1] = chunks_bits[-1].ljust(MATCH_BITS, '0')

    num_chunks = len(chunks_bits)
    from_wallets = generate_btc_keypairs_from_seed(SEED_A, num_chunks)

    # 获取第一个未用的 SEED_B 钱包
    to_wallet = get_first_unused_seed_b_wallet(from_user)
    if not to_wallet:
        print("[✗] 所有 SEED_B 地址都已使用，无法发送消息。")
        return 0
    else:
        print(f"[i] 发送到钱包: {to_wallet[2]}")

    success_count = 0
    for i, chunk_bits in enumerate(chunks_bits):
        from_wallet = from_wallets[i]
        chunk_suffix = chunk_bits[-MATCH_BITS:] if len(chunk_bits) >= MATCH_BITS else chunk_bits
        matched = False
        print(f"[>] 匹配第 {i + 1}/{len(chunks_bits)} 块 ...")
        for attempt in range(max_attempts):
            amount = round(0.0 + attempt * step, 2)
            from_privkey_hex = from_wallet[0]
            from_address = from_wallet[2]
            to_address = to_wallet[2]
            last_block = bc.get_last_block()
            now_block_index = last_block.index + 1
            prev_block_hash = last_block.hash

            tx = {"from": from_address, "to": to_address, "amount": amount}

            block_hash_hex, block_hash_bits, timestamp = simulate_block_hash_future_block(
                from_address, to_address, amount, from_privkey_hex,
                prev_block_hash, index=now_block_index, future_offset=1.0
            )
            if block_hash_bits.endswith(chunk_suffix):
                print(f"[✓] 匹配成功: chunk={i}, amount={amount}, hash={block_hash_hex}, hash_suffix={block_hash_bits[-MATCH_BITS:]}, timestamp={timestamp}")
                send_transaction(tx, system, from_user, timestamp)
                matched = True
                success_count += 1
                break

        if not matched:
            print(f"[✗] 匹配失败: chunk {i}")

    print(f"[✔] 全部完成，共成功匹配 {success_count}/{len(chunks_bits)} 块。")
    return success_count


# ------------------ 解密函数 ------------------
def decrypt_from_transactions(user):
    """
    从区块链系统中解码隐藏信息。
    system: Blockchain 实例，需支持 get_all_transactions(user)
    user: 当前用户对象（其下所有交易由 get_all_transactions 提供）
    """
    end_marker_bits = ''.join(format(b, '08b') for b in END_MARKER.encode('utf-8'))

    # 使用最后一个已用 SEED_B 地址进行匹配
    last_wallet = get_last_used_seed_b_wallet(user)
    to_address = last_wallet[2]
    print(f"[i] 解密使用钱包: {to_address}")

    from_wallets = generate_btc_keypairs_from_seed(SEED_A, 999)
    from_addrs = [w[2] for w in from_wallets]

    user_txs = bc.get_transactions_by_address(to_address)
    if not user_txs:
        return None

    matched_txs = []
    for addr in from_addrs:
        related = [tx for tx in user_txs if tx["from"] == addr]
        if related:
            matched_txs.append(related[0])

    msg_bits = ""
    for i, tx in enumerate(matched_txs):
        block_hash = tx.get("block_hash")
        bits = hex_to_bits(block_hash)
        msg_bits += bits[-MATCH_BITS:]
        idx = msg_bits.find(end_marker_bits)
        if idx != -1:
            msg_bits = msg_bits[:idx]
            break

    msg_bytes = bytes(int(msg_bits[i:i + 8], 2) for i in range(0, len(msg_bits), 8) if len(msg_bits[i:i + 8]) == 8)
    try:
        return msg_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def get_unused_seed_b_address(user):
    """
    返回 SEED_B 地址集中第一个未被用于消息传输的可用地址
    user: 当前用户对象，用于查询相关交易
    """
    # 生成 SEED_B 的地址集
    seed_b_wallets = generate_btc_keypairs_from_seed(SEED_B, MAX_ADDR_LENGTH)
    seed_b_addrs = [w[2] for w in seed_b_wallets]

    # 获取用户所有交易，提取所有接收方地址
    user_txs = bc.get_all_transactions(user)
    used_addrs = set(tx["to"] for tx in user_txs)

    # 找到第一个未被使用的地址
    for addr in seed_b_addrs:
        if addr not in used_addrs:
            print(f"[✓] 可用地址: {addr}")
            return addr

    print("[✗] 所有 SEED_B 地址都已被使用")
    return None


def get_used_seed_b_addresses(user) -> list:
    """
    获取 SEED_B 地址集中所有已经被用于消息传输的地址
    返回列表形式
    """
    # 生成 SEED_B 的地址集
    seed_b_wallets = generate_btc_keypairs_from_seed(SEED_B, MAX_ADDR_LENGTH)
    seed_b_addrs = set(w[2] for w in seed_b_wallets)

    # 获取用户所有交易，提取所有接收方地址
    user_txs = bc.get_all_transactions(user)
    if not user_txs:
        print("[i] 用户没有交易记录")
        return []

    # 找到 SEED_B 地址集中已经使用的地址
    used_addrs = set(tx["to"] for tx in user_txs if tx["to"] in seed_b_addrs)
    print(f"[i] 已使用的 SEED_B 地址数量: {len(used_addrs)}")
    return list(used_addrs)


def get_seed_b_wallets():
    """
    返回 SEED_B 的钱包三元组列表 (priv, pub, addr)
    """
    return generate_btc_keypairs_from_seed(SEED_B, MAX_ADDR_LENGTH)


def get_first_unused_seed_b_wallet(user):
    """
    返回第一个未被用于消息传输的 SEED_B 钱包 (priv, pub, addr)
    """
    seed_b_wallets = get_seed_b_wallets()
    user_txs = bc.get_all_transactions(user)
    used_addrs = set(tx["to"] for tx in user_txs if tx['from'] != 'SYSTEM') if user_txs else set()

    for w in seed_b_wallets:
        if w[2] not in used_addrs:
            return w
    return None  # 全部用过


def get_last_used_seed_b_wallet(user):
    """
    返回最后一个已使用的 SEED_B 钱包 (priv, pub, addr)
    """
    seed_b_wallets = get_seed_b_wallets()
    user_txs = bc.get_all_transactions(user)
    if not user_txs:
        return None

    # 找到所有 SEED_B 地址中被使用的地址
    used_wallets = [w for w in seed_b_wallets if any(tx["to"] == w[2] for tx in user_txs if tx['from'] != 'SYSTEM')]
    return used_wallets[-1] if used_wallets else None


# ------------------ 可选：获取完整比特流 ------------------
def get_bitstream_from_transactions(transactions: List[dict]) -> str:
    """
    返回整个消息的比特流（含补齐位），用于调试或网络传输。
    """
    if not transactions:
        print("[!] 无交易数据")
        return ""

    chunks_bits = [tx["chunk"] for tx in sorted(transactions, key=lambda x: x["chunk_index"])]
    bitstream = ''.join(chunks_bits)
    print(f"[i] 比特流总长度: {len(bitstream)} bits")
    return bitstream

