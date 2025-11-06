import itertools
import base58
from blockchain import blockchain
from config import END_MARKER, MESSAGE
from users.user import User
from utils.utils_crypto import btc_keypair_stream

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def generate_address_base58(seed, batch_size=3, max_attempts=1_000_000):
    """
    生成覆盖所有 Base58 字母组合（长度=batch_size）的地址集合。

    返回:
        wallets: List[Dict] - 每个元素包含 {'private','public','address'}
        combo_mapping: Dict[str, Tuple[address,pos]]
            每个组合(如 'C58') → 第一次出现的地址与起始位置
        attempts: int - 尝试次数
    """
    all_combos = {''.join(c) for c in itertools.product(BASE58_ALPHABET, repeat=batch_size)}
    combo_mapping = {}
    seen_combos = set()

    wallet_stream = btc_keypair_stream(seed)
    wallets = []
    attempts = 0

    while seen_combos != all_combos and attempts < max_attempts:
        attempts += 1
        privkey, pubkey, addr = next(wallet_stream)

        # 预先把每个字符对应的位置列表做出来（加速查找）
        char_positions = {}
        for idx, ch in enumerate(addr):
            char_positions.setdefault(ch, []).append(idx)

        new_found = []
        addr_len = len(addr)
        # 枚举地址中按位置升序的 index 组合，生成地址实际包含的组合（按地址顺序）
        # combinations(range(addr_len), batch_size) 的数量通常远小于 全组合空间
        for indices in itertools.combinations(range(addr_len), batch_size):
            combo_chars = ''.join(addr[i] for i in indices)  # 例如 'A3z'
            if combo_chars in all_combos and combo_chars not in seen_combos:
                # 记录的是字符在地址中的具体位置列表
                combo_mapping[combo_chars] = (addr, list(indices))
                seen_combos.add(combo_chars)
                new_found.append(combo_chars)

        if new_found:
            wallets.append({
                "private": privkey,
                "public": pubkey,
                "address": addr,
                "found_combos": new_found  # 可选：便于调试/日志
            })

    missing = all_combos - seen_combos
    if missing:
        raise Exception("组合空间未完全覆盖")

    # print(f"[✓] 尝试 {attempts} 次，生成地址数 {len(wallets)}，已映射组合数 {len(seen_combos)}")
    return wallets, combo_mapping, attempts


def encrypt_and_send(system, from_address, seed, message=MESSAGE, batch_size=3):
    """
    发送消息时，每笔交易传一个 batch_size 组合（如 "C58"），
    并将组合说明书写入 OP_RETURN。
    """
    full_message = message + END_MARKER
    message_base58 = base58.b58encode(full_message.encode()).decode('utf-8')

    # 生成组合映射
    to_wallets, combo_mapping, _ = generate_address_base58(seed, batch_size=batch_size)

    bob = User.load('Bob')
    for w in to_wallets:
        system.add_custom_wallet(bob, w['private'], w['public'], w['address'])

    tx_records = []
    i = 0

    while i < len(message_base58):
        combo = message_base58[i:i + batch_size]
        combo_num = len(combo)
        if combo_num < batch_size:
            # 最后不足一组时补齐
            combo = combo.ljust(batch_size, '1')  # 用 '1' 补齐
        if combo not in combo_mapping:
            raise ValueError(f"组合 {combo} 无对应地址")

        to_addr, pos_list = combo_mapping[combo]
        pos_list = pos_list[:combo_num]
        op_str = "-".join(map(str, pos_list))
        amount = 0.00000001

        # 在交易中携带组合映射信息
        system.transfer(from_address, to_addr, amount, op_return=op_str)
        tx_records.append(op_str)
        i += batch_size

    # print(f"[✓] 已发送 {len(tx_records)} 笔交易，每笔携带 {batch_size} 个字符组合")
    return tx_records


def decrypt_from_transactions(seed, batch_size=3):
    """
    解码时从 OP_RETURN 恢复完整 Base58 组合序列。
    """
    to_wallets, combo_mapping, _ = generate_address_base58(seed, batch_size=batch_size)
    addr_to_combo = {addr: combo for combo, (addr, pos) in combo_mapping.items()}
    to_addresses = [w['address'] for w in to_wallets]

    all_txs = []
    for address in to_addresses:
        all_txs.extend(blockchain.get_transactions_by_address(address))
    all_txs.sort(key=lambda tx: tx['timestamp'])

    combos_received = []

    for tx in all_txs:
        to_address = tx['to']
        if not tx.get('op_return'):
            continue

        try:
            pos = tx['op_return'].split(":")[0].split("-")
            combo = ""
            for i in pos:
                combo += to_address[int(i)]
            combos_received.append(combo)

        except Exception:
            raise Exception("无效的 OP_RETURN 数据")

    if not combos_received:
        raise Exception("未找到有效组合")

    message_base58 = "".join(combos_received)

    try:
        msg_bytes = base58.b58decode(message_base58)
        decoded_message = msg_bytes.decode("utf-8", errors="ignore")

        if END_MARKER in decoded_message:
            decoded_message = decoded_message.split(END_MARKER)[0]
            return decoded_message
        else:
            raise Exception("未找到结束标志")

    except Exception as e:
        raise Exception(f"Base58 解码失败: {e}")
