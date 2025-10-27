import hashlib
import json
from tqdm import tqdm
from blockchain.transaction import Transaction
from blockchain import blockchain
from system import system
from users.user import User
from utils.utils_crypto import sign_message, generate_btc_keypairs_from_seed, btc_keypair_stream
from utils.utils import hex_to_bits
from config import MESSAGE, MATCH_BITS, END_MARKER
from utils.utils_wallets import init_walltes_from_seed, get_wallet_from_address

r_bits = MATCH_BITS
num_receiver_addresses = 2 ** r_bits


def generate_address_mappings(seed):
    """
    生成地址映射（双向）:
        bit_pattern -> address
        address -> bit_pattern
    要求：
        取地址的 SHA256 哈希前 r_bits 位作为标识，
        直到覆盖所有 2**r_bits 种可能的比特组合。
    """
    r_bits = MATCH_BITS
    num_patterns = 2 ** r_bits

    # 初始化
    wallet_stream = btc_keypair_stream(seed)

    all_patterns = [format(i, f'0{r_bits}b') for i in range(num_patterns)]
    forward_mapping = {pattern: None for pattern in all_patterns}
    reverse_mapping = {}

    found_count = 0
    checked = 0
    max_attempts = num_patterns * 200  # 防止极端情况死循环

    # 保存钱包信息
    wallets = []

    # print(f"[i] 正在生成地址映射：目标 {num_patterns} 种 {r_bits}-bit 模式...")

    # 主循环
    while found_count < num_patterns and checked < max_attempts:
        checked += 1
        privkey, pubkey, addr = next(wallet_stream)

        # 地址哈希前缀比特
        addr_hash = hashlib.sha256(addr.encode()).hexdigest()
        addr_bits = hex_to_bits(addr_hash)
        prefix = addr_bits[:r_bits]

        # 匹配pattern
        if prefix in forward_mapping and forward_mapping[prefix] is None:
            wallets.append({
                'private': privkey,
                'public': pubkey,
                'address': addr
            })

            forward_mapping[prefix] = addr
            reverse_mapping[addr] = prefix
            found_count += 1

            # 进度提示
            # if found_count % 64 == 0 or found_count == num_patterns:
            # print(f"[i] 已匹配 {found_count}/{num_patterns} 种前缀...")

    # 检查结果
    missing = [k for k, v in forward_mapping.items() if v is None]
    if missing:
        raise Exception("无法覆盖所有比特模式")
        # print(f"[!] 未能覆盖的比特模式 {len(missing)} 种，例如: {missing[:5]}")
    # else:
    #     print(f"[✔] 映射生成完成：已覆盖全部 {num_patterns} 种 {r_bits}-bit 模式。")

    return forward_mapping, reverse_mapping, wallets


def encrypt_and_send(system, from_address, seed, message=MESSAGE):
    """发送消息"""
    full_message = message + END_MARKER
    msg_bits = ''.join(format(b, '08b') for b in full_message.encode("utf-8"))
    # print(f"[i] 发送消息: {msg_bits}")

    # 分 r-bit 块
    chunks_bits = [msg_bits[i:i + r_bits] for i in range(0, len(msg_bits), r_bits)]
    if len(chunks_bits[-1]) < r_bits:
        chunks_bits[-1] = chunks_bits[-1].ljust(r_bits, '0')

    # print(f"[i] 消息切分为 {len(chunks_bits)} 个 {r_bits}-bit 块")

    # 映射表
    receiver_mapping, _, to_wallets = generate_address_mappings(seed)

    # 验证接收方地址存在
    bob = User.load('Bob')
    for index, (private, public, address) in enumerate(to_wallets):
        system.add_custom_wallet(bob, private, public, address)

    success_count = 0

    for i, chunk_bits in enumerate(chunks_bits):
        to_address = receiver_mapping.get(chunk_bits)
        if not to_address:
            raise ValueError("接收方地址不存在")

        # 创建交易
        amount = 0.00000001
        system.transfer(from_address, to_address, amount)
        success_count += 1
    return True


def decrypt_from_transactions(seed):
    """接收并解码消息"""
    _, receiver_mapping, to_wallets = generate_address_mappings(seed)
    receive_txs = []
    for to_address, bits in receiver_mapping.items():
        txs = blockchain.get_transactions_by_address(to_address)
        for tx in txs:
            receive_txs.append({
                "to": tx["to"],
                "timestamp": tx["timestamp"]
            })
    receive_txs.sort(key=lambda x: x["timestamp"])

    if not receive_txs:
        print("[!] 没有找到消息交易")
        return None

    message_bits = ""
    end_marker_bits = ''.join(format(b, '08b') for b in END_MARKER.encode('utf-8'))

    for tx in receive_txs:
        chunk_bits = receiver_mapping[tx["to"]]
        if chunk_bits:
            message_bits += chunk_bits
            if end_marker_bits in message_bits:
                message_bits = message_bits[:message_bits.find(end_marker_bits)]
                break

    if not message_bits:
        print("[!] 没有提取到有效比特数据")
        return None

    try:
        msg_bytes = bytes(
            int(message_bits[i:i + 8], 2)
            for i in range(0, len(message_bits), 8)
            if len(message_bits[i:i + 8]) == 8
        )
        decoded_message = msg_bytes.decode("utf-8")
        print(f"[✓] 消息解码成功: {decoded_message}")
        return decoded_message
    except (ValueError, UnicodeDecodeError) as e:
        print(f"[✗] 消息解码失败: {e}")
        return None
