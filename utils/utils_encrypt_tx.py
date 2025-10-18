import hashlib
import json
import time
from blockchain.transaction import Transaction
from blockchain.blockchain import bc
from utils.utils_crypto import sign_message, generate_btc_keypairs_from_seed
from typing import List
from config import SEED_A, SEED_B, MESSAGE, MATCH_BITS, END_MARKER, MAX_ADDR_LENGTH


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
    """
    将消息编码为比特块，打乱顺序后根据哈希后缀匹配执行交易
    一旦某块匹配成功，就立即发出交易
    """
    if not message:
        message = MESSAGE

    # 拼接消息结束符
    full_message = message + END_MARKER
    msg_bytes = full_message.encode("utf-8")
    msg_bits = ''.join(format(b, '08b') for b in msg_bytes)
    print(f"[i] 原始消息比特流 ({len(msg_bits)} bits):\n{msg_bits}")

    # 同时打印原始消息和结束符的比特流
    message_bits = ''.join(format(b, '08b') for b in message.encode("utf-8"))
    end_marker_bits = ''.join(format(b, '08b') for b in END_MARKER.encode("utf-8"))
    print(f"[i] 消息比特流 ({len(message_bits)} bits):\n{message_bits}")
    print(f"[i] 结束符比特流 ({len(end_marker_bits)} bits):\n{end_marker_bits}")

    # 切分为固定比特块
    chunks_bits = [msg_bits[i:i + MATCH_BITS] for i in range(0, len(msg_bits), MATCH_BITS)]
    if len(chunks_bits[-1]) < MATCH_BITS:
        chunks_bits[-1] = chunks_bits[-1].ljust(MATCH_BITS, '0')

    # 打乱顺序
    # random.shuffle(chunks_bits)
    # print(f"[i] 已打乱消息块顺序，共 {len(chunks_bits)} 块")

    # 钱包初始化
    from_wallets = generate_btc_keypairs_from_seed(SEED_A, MAX_ADDR_LENGTH)
    to_wallets = generate_btc_keypairs_from_seed(SEED_B, 1)
    to_wallet = to_wallets[0]

    success_count = 0

    # 遍历每一个随机后的 bit 块
    for i, chunk_bits in enumerate(chunks_bits):
        from_wallet = from_wallets[i % len(from_wallets)]
        chunk_suffix = chunk_bits[-MATCH_BITS:] if len(chunk_bits) >= MATCH_BITS else chunk_bits

        matched = False
        print(f"[>] 匹配第 {i + 1}/{len(chunks_bits)} 块 ...")
        # 遍历金额区间，尝试匹配哈希后缀
        for attempt in range(max_attempts):
            amount = round(0.0 + attempt * step, 2)
            from_privkey_hex = from_wallet[0]
            from_address = from_wallet[2]
            to_address = to_wallet[2]
            last_bloclk = bc.get_last_block()
            now_block_index = last_bloclk.index + 1
            prev_block_hash =last_bloclk.hash

            tx = {
                "from": from_wallet[2],
                "to": to_wallet[2],
                "amount": amount
            }

            # 模拟哈希
            block_hash_hex, block_hash_bits, timestamp = simulate_block_hash_future_block(from_address, to_address, amount, from_privkey_hex, prev_block_hash, index=now_block_index, future_offset=1.0)
            if block_hash_bits.endswith(chunk_suffix):
                print(f"[✓] 匹配成功: chunk={i}, amount={amount}, hash={block_hash_hex}, hash_suffix={block_hash_bits[-MATCH_BITS:]}, timestamp={timestamp}")
                send_transaction(tx, system, from_user, timestamp)
                matched = True
                success_count += 1
                prev_block_hash = block_hash_hex
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

    # 1️ 生成发送方地址集（即消息嵌入时使用的地址）
    from_wallets = generate_btc_keypairs_from_seed(SEED_A, MAX_ADDR_LENGTH)
    from_addrs = [w[2] for w in from_wallets]
    print(f"[i] 已生成 {len(from_addrs)} 个发送地址，用于匹配交易。")

    # 2️ 获取用户所有交易
    user_txs = bc.get_all_transactions(user)
    if not user_txs:
        print("[✗] 未找到任何用户相关交易。")
        return None
    print(f"[i] 共找到 {len(user_txs)} 条用户相关交易。")

    # 3️ 按生成地址的顺序提取相关交易
    matched_txs = []
    for addr in from_addrs:
        # 找到此地址发起的交易（可能多条）
        related = [tx for tx in user_txs if tx["from"] == addr]
        if related:
            # 通常每个地址只发一次交易（加密逻辑中是如此）
            matched_txs.append(related[0])
    print(f"[i] 共匹配到 {len(matched_txs)} 条相关交易。")

    if not matched_txs:
        print("[✗] 没有匹配到任何相关交易。")
        return None

    # 4️ 从交易哈希提取比特末尾信息
    msg_bits = ""
    for i, tx in enumerate(matched_txs):
        block_hash = tx.get("block_hash")
        bits = hex_to_bits(block_hash)
        # 取末尾 MATCH_BITS 位
        print(f"[>] 解析第 {i + 1}/{len(matched_txs)} 条交易 ...")
        print(f"    区块哈希: {block_hash}")
        print(f"    末尾 {MATCH_BITS} 位: {bits[-MATCH_BITS:]}")
        msg_bits += bits[-MATCH_BITS:]
        # 检查是否包含 END_MARKER bits
        idx = msg_bits.find(end_marker_bits)
        if idx != -1:
            print(f"[i] 找到消息结束符{end_marker_bits}，截断比特流至 {idx} 位。")
            # 截断到 END_MARKER 位置
            msg_bits = msg_bits[:idx]
            break

    # 5️ 转回字节 → 字符串
    # 先打印完整的比特流
    print(f"[i] 提取的完整比特流 ({len(msg_bits)} bits):\n{msg_bits}")

    # 分割为8位一组用于转换为字节
    msg_bytes_data = []
    for i in range(0, len(msg_bits), 8):
        byte_chunk = msg_bits[i:i+8]
        if len(byte_chunk) == 8:  # 只处理完整的字节
            msg_bytes_data.append(int(byte_chunk, 2))

    msg_bytes = bytes(msg_bytes_data)
    print(f"[i] 解码后的字节数据: {msg_bytes}")

    try:
        full_msg = msg_bytes.decode("utf-8")
        print(f"[✓] 解码成功，消息内容如下：\n{full_msg}")
        return full_msg
    except UnicodeDecodeError as e:
        print(f"[✗] 解码失败，无法将字节转换为UTF-8字符串: {e}")
        return None


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
