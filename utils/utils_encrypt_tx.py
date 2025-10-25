import hashlib
import json
import time
from blockchain import blockchain
from blockchain.transaction import Transaction
from utils.utils import hex_to_bits
from utils.utils_wallets import get_first_unused_seed_b_wallet, get_last_used_seed_b_wallet
from utils.utils_transaction import send_transaction
from utils.utils_crypto import sign_message, generate_btc_keypairs_from_seed
from config import SEED_A, MESSAGE, MATCH_BITS, END_MARKER


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


# ------------------ 主逻辑函数 ------------------
def encrypt_and_send(system, from_user, message=None, max_attempts=1000, step=1):
    if not message:
        message = MESSAGE

    if from_user.username != 'Alice':
        return None

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
            amount_satoshi = 0 + step * attempt
            amount = amount_satoshi / 100_000_000
            from_privkey_hex = from_wallet[0]
            from_address = from_wallet[2]
            to_address = to_wallet[2]
            last_block = blockchain.get_last_block()
            now_block_index = last_block.index + 1
            prev_block_hash = last_block.hash

            tx = {"from": from_address, "to": to_address, "amount": amount}

            block_hash_hex, block_hash_bits, timestamp = simulate_block_hash_future_block(
                from_address, to_address, amount, from_privkey_hex,
                prev_block_hash, index=now_block_index, future_offset=1.0
            )
            if block_hash_bits.endswith(chunk_suffix):
                print(f"[✓] 匹配成功: chunk={i}, amount={amount:.8f}, hash={block_hash_hex}, hash_suffix={block_hash_bits[-MATCH_BITS:]}, timestamp={timestamp}")
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

    if user.username != 'Bob':
        return None

    # 使用最后一个已用 SEED_B 地址进行匹配
    last_wallet = get_last_used_seed_b_wallet(user)
    to_address = last_wallet[2]
    print(f"[i] 解密使用钱包: {to_address}")

    from_wallets = generate_btc_keypairs_from_seed(SEED_A, 999)
    from_addrs = [w[2] for w in from_wallets]

    user_txs = blockchain.get_transactions_by_address(to_address)
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
