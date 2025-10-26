import hashlib
import json
import time
from blockchain import blockchain
from blockchain.block import Block
from blockchain.transaction import Transaction
from users.user import User
from utils.utils import hex_to_bits
from utils.utils_users import get_user_from_wallet
from utils.utils_wallets import get_wallet_from_address, init_walltes_from_seed
from utils.utils_crypto import sign_message, btc_keypair_stream
from config import MESSAGE, MATCH_BITS, END_MARKER


# ------------------ 模拟函数 ------------------
def simulate_tx_hash_future(from_addr, to_addr, amount, from_privkey_hex):
    """
    模拟一个交易在未来时间生成的 tx_hash，并返回 tx_hash 及其二进制比特串
    """
    # 构造交易
    message = f"{from_addr}->{to_addr}:{amount}"
    signature_hex = sign_message(from_privkey_hex, message)
    tx = Transaction(from_addr, to_addr, amount, signature_hex)

    # 计算交易哈希
    tx_hash = tx.compute_hash()
    tx_hash_bits = hex_to_bits(tx_hash)

    # print(f"模拟交易: from={from_addr}, to={to_addr}, amount={amount}, tx_hash={tx_hash}")

    return tx_hash, tx_hash_bits


# ------------------ 主逻辑函数 ------------------
def encrypt_and_send(system, from_address, seed, message=MESSAGE, max_attempts=1000, step=1):
    # 将消息和结束符单独转成比特流
    message_bytes = message.encode("utf-8")
    message_bits = ''.join(format(b, '08b') for b in message_bytes)
    # print(f"[i] 消息比特流 ({len(message_bits)} bits):\n{message_bits}")

    end_bytes = END_MARKER.encode("utf-8")
    end_bits = ''.join(format(b, '08b') for b in end_bytes)
    # print(f"[i] 结束符比特流 ({len(end_bits)} bits):\n{end_bits}")

    # 拼接完整消息
    full_message = message + END_MARKER
    full_bytes = full_message.encode("utf-8")
    full_bits = ''.join(format(b, '08b') for b in full_bytes)
    # print(f"[i] 拼接后的完整比特流 ({len(full_bits)} bits):\n{full_bits}")

    # 切分为固定比特块
    chunks_bits = [full_bits[i:i + MATCH_BITS] for i in range(0, len(full_bits), MATCH_BITS)]
    if len(chunks_bits[-1]) < MATCH_BITS:
        chunks_bits[-1] = chunks_bits[-1].ljust(MATCH_BITS, '0')

    num_chunks = len(chunks_bits)
    from_wallet = get_wallet_from_address(from_address)
    from_privkey_hex = from_wallet['private']

    # 验证接收方地址存在
    bob = User.load('Bob')
    to_wallets = init_walltes_from_seed(system, bob, seed, num_chunks)

    success_count = 0
    for i, chunk_bits in enumerate(chunks_bits):
        chunk_suffix = chunk_bits[-MATCH_BITS:] if len(chunk_bits) >= MATCH_BITS else chunk_bits
        matched = False
        print(f"[>] 匹配第 {i + 1}/{len(chunks_bits)} 块 ...")
        for attempt in range(max_attempts):
            to_wallet = to_wallets[i]
            amount_satoshi = 0 + step * attempt
            amount = amount_satoshi / 100_000_000
            to_address = to_wallet[2]
            simulate_tx_hash, simulate_tx_hash_bits = simulate_tx_hash_future(from_address, to_address, amount, from_privkey_hex)
            if simulate_tx_hash_bits.endswith(chunk_suffix):
                # print(f"[✓] 匹配成功: chunk={i}, amount={amount:.8f}, to_address={to_address}, tx_hash={simulate_tx_hash}, hash_suffix={simulate_tx_hash_bits[-MATCH_BITS:]}")
                _, _, tx_hash = system.transfer(from_address, to_address, amount)
                if not tx_hash == simulate_tx_hash:
                    # print(f"[✗] 匹配失败: chunk {i}, amount={amount:.8f}, to_address={to_address}, tx_hash={tx_hash}")
                    raise ValueError("匹配失败")
                matched = True
                success_count += 1
                break
        if not matched:
            print(f"[✗] 匹配失败: chunk {i}")
    # print(f"[✔] 全部完成，共成功匹配 {success_count}/{len(chunks_bits)} 块。")
    return success_count


# ------------------ 解密函数 ------------------
def decrypt_from_transactions(seed):
    """
    从区块链系统中解码隐藏信息。
    system: Blockchain 实例，需支持 get_all_transactions(user)
    user: 当前用户对象（其下所有交易由 get_all_transactions 提供）
    """
    end_marker_bits = ''.join(format(b, '08b') for b in END_MARKER.encode('utf-8'))

    # 初始化接收地址
    to_wallet_stream = btc_keypair_stream(seed)
    to_wallet = next(to_wallet_stream)
    to_address = to_wallet[2]

    msg_bits = ""
    i = 0
    max_try_count = 2000
    while i < max_try_count:
        txs = blockchain.get_transactions_by_address(to_address)
        if not txs:
            raise ValueError("没有找到交易")
        tx = txs[0]
        to_address = next(to_wallet_stream)[2]
        tx_hash = tx.get("tx_hash")
        bits = hex_to_bits(tx_hash)
        msg_bits += bits[-MATCH_BITS:]
        # print(f"[i] 获取 {to_address} 的交易哈希 {tx_hash} {bits} {msg_bits}")
        idx = msg_bits.find(end_marker_bits)
        if idx != -1:
            msg_bits = msg_bits[:idx]
            break

    # print(f"[i] 获取消息 ({len(msg_bits)} bits):\n{msg_bits}")
    msg_bytes = bytes(int(msg_bits[i:i + 8], 2) for i in range(0, len(msg_bits), 8) if len(msg_bits[i:i + 8]) == 8)
    # print(f"[i] 解密结果 ({len(msg_bytes)} bytes):\n{msg_bytes}")
    try:
        msg = msg_bytes.decode("utf-8", errors="ignore")  # 忽略非法字节
        return msg
    except UnicodeDecodeError:
        raise ValueError("解码失败")
