import hashlib
import json
from tqdm import tqdm
from blockchain.transaction import Transaction
from blockchain import blockchain
from utils.utils_crypto import sign_message, generate_btc_keypairs_from_seed
from config import SEED_A, SEED_B, MESSAGE, MATCH_BITS, END_MARKER, MAX_ADDR_LENGTH

r_bits = MATCH_BITS
num_receiver_addresses = 2 ** r_bits


# ---------------- 核心工具函数 ----------------

def hex_to_bits(hex_hash: str) -> str:
    """十六进制哈希转 256-bit 二进制"""
    hex_hash = hex_hash.strip().lower().replace("0x", "")
    return bin(int(hex_hash, 16))[2:].zfill(256)


def init_sender_wallet(system, user):
    """初始化发送方钱包"""
    wallets = generate_btc_keypairs_from_seed(SEED_A, 1)
    priv, pub, addr = wallets[0]

    created, _, _ = system.add_custom_wallet(user.username, priv, pub, addr)
    if created:
        blockchain.faucet(addr, 1000)
    else:
        wallet_balance = system.blockchain.get_balance(addr)
        if wallet_balance < 999:
            blockchain.faucet(addr, int(1000 - wallet_balance))

    print(f"[✓] 发送方钱包初始化完成: {addr}")
    return priv, pub, addr


def init_receiver_wallets(system, user):
    """初始化接收方钱包池"""
    wallets = generate_btc_keypairs_from_seed(SEED_B, num_receiver_addresses)
    for priv, pub, addr in tqdm(wallets, desc="初始化接收方钱包", unit="个"):
        created, _, _ = system.add_custom_wallet(user.username, priv, pub, addr)
        if created:
            blockchain.faucet(addr, 1000)
        else:
            wallet_balance = system.blockchain.get_balance(addr)
            if wallet_balance < 999:
                blockchain.faucet(addr, int(1000 - wallet_balance))
    print(f"[✓] 接收方钱包初始化完成，共 {len(wallets)} 个地址。")
    return wallets


def generate_receiver_address_mapping():
    """生成接收方地址映射: r-bit -> 地址"""
    wallets = generate_btc_keypairs_from_seed(SEED_B, num_receiver_addresses)
    address_mapping = {}
    for i, (_, _, addr) in enumerate(wallets):
        bit_pattern = format(i, f'0{r_bits}b')
        address_mapping[bit_pattern] = addr
    return address_mapping


def send_message(system, from_user, message=None):
    """发送消息"""
    if not message:
        message = MESSAGE

    if from_user.username != 'Alice':
        return None

    full_message = message + END_MARKER
    msg_bits = ''.join(format(b, '08b') for b in full_message.encode("utf-8"))
    print(f"[i] 发送消息: {msg_bits}")

    # 分 r-bit 块
    chunks_bits = [msg_bits[i:i + r_bits] for i in range(0, len(msg_bits), r_bits)]
    if len(chunks_bits[-1]) < r_bits:
        chunks_bits[-1] = chunks_bits[-1].ljust(r_bits, '0')

    print(f"[i] 消息切分为 {len(chunks_bits)} 个 {r_bits}-bit 块")

    # 映射表
    receiver_mapping = generate_receiver_address_mapping()
    sender_wallet = generate_btc_keypairs_from_seed(SEED_A, 1)[0]
    from_privkey, from_pubkey, from_address = sender_wallet

    transaction_sequence = []
    success_count = 0

    for i, chunk_bits in enumerate(chunks_bits):
        to_address = receiver_mapping.get(chunk_bits)
        if not to_address:
            print(f"[✗] 无法找到比特模式 {chunk_bits} 的地址")
            continue

        # 创建交易
        amount = 0.00000001

        success, msg, tx_hash, block_hash = system.transfer(
            from_user, from_address, to_address, amount
        )

        if success:
            print(f"[✓] 块 {i+1} 发送成功: {chunk_bits} -> {to_address}")
            success_count += 1
            transaction_sequence.append({
                "chunk_index": i,
                "chunk_bits": chunk_bits,
                "to_address": to_address,
                "tx_hash": tx_hash,
                "block_hash": block_hash
            })
        else:
            print(f"[✗] 块 {i+1} 发送失败: {chunk_bits}")

    print(f"[✔] 消息发送完成: 成功 {success_count}/{len(chunks_bits)} 块")
    return transaction_sequence


def receive_message(user):
    """接收并解码消息"""
    if user.username != 'Bob':
        return None

    receiver_mapping = generate_receiver_address_mapping()
    reverse_mapping = {addr: bits for bits, addr in receiver_mapping.items()}

    user_txs = blockchain.get_all_transactions(user)
    receive_txs = [
        tx for tx in user_txs
        if tx.get("to") in reverse_mapping and tx.get("from") != "SYSTEM"
    ]
    receive_txs.sort(key=lambda x: x.get("timestamp", 0))

    if not receive_txs:
        print("[!] 没有找到消息交易")
        return None

    message_bits = ""
    end_marker_bits = ''.join(format(b, '08b') for b in END_MARKER.encode('utf-8'))

    for tx in receive_txs:
        chunk_bits = reverse_mapping.get(tx.get("to"))
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


def analyze_transactions(user):
    """调试分析: 比特序列与地址序列"""
    if user.username != 'Bob':
        return None

    receiver_mapping = generate_receiver_address_mapping()
    reverse_mapping = {addr: bits for bits, addr in receiver_mapping.items()}

    user_txs = blockchain.get_all_transactions(user)
    receive_txs = [
        tx for tx in user_txs
        if tx.get("to") in reverse_mapping and tx.get("from") != "SYSTEM"
    ]
    receive_txs.sort(key=lambda x: x.get("timestamp", 0))

    analysis = {
        "total_transactions": len(receive_txs),
        "bit_sequence": [],
        "address_sequence": []
    }

    for tx in receive_txs:
        chunk_bits = reverse_mapping.get(tx.get("to"))
        if chunk_bits:
            analysis["bit_sequence"].append(chunk_bits)
            analysis["address_sequence"].append(tx.get("to"))

    return analysis
