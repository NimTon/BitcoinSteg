from tqdm import tqdm
from blockchain import blockchain
from config import SEED_A, MAX_ADDR_LENGTH, SEED_B, SYSTEM_PUBLIC_KEY
from users.user import User
from utils.utils import load_json
from utils.utils_crypto import generate_btc_keypairs_from_seed


def init_seed_a_wallets(system, user):
    """
    初始化 SEED_A 地址集 (发送方钱包)
    - 为用户创建 MAX_ADDR_LENGTH 个钱包
    - 每个钱包注入 1000 单位资金
    """
    wallets = generate_btc_keypairs_from_seed(SEED_A, MAX_ADDR_LENGTH)
    for i, (priv, pub, addr) in enumerate(tqdm(wallets, desc="初始化SEED_A钱包", unit="个"), start=1):
        created, _, _ = system.add_custom_wallet(user.username, priv, pub, addr)
        if created:
            blockchain.faucet(addr, 1000)
        else:
            wallet_balance = system.blockchain.get_balance(addr)
            if wallet_balance < 999:
                blockchain.faucet(addr, int(1000 - wallet_balance))
    tqdm.write(f"[✓] SEED_A 钱包初始化完成，共 {len(wallets)} 个。")
    return wallets


def init_seed_b_wallets(system, user):
    """
    初始化 SEED_B 地址集 (接收方钱包)
    - 为用户创建 MAX_ADDR_LENGTH 个钱包
    - 每个钱包注入 1000 单位资金
    """
    wallets = generate_btc_keypairs_from_seed(SEED_B, MAX_ADDR_LENGTH)
    for i, (priv, pub, addr) in enumerate(tqdm(wallets, desc="初始化SEED_B钱包", unit="个"), start=1):
        created, _, _ = system.add_custom_wallet(user.username, priv, pub, addr)
        if created:
            blockchain.faucet(addr, 1000)
        else:
            wallet_balance = system.blockchain.get_balance(addr)
            if wallet_balance < 999:
                blockchain.faucet(addr, int(1000 - wallet_balance))
    tqdm.write(f"[✓] SEED_A 钱包初始化完成，共 {len(wallets)} 个。")
    return wallets


def get_unused_seed_b_address(user):
    """
    返回 SEED_B 地址集中第一个未被用于消息传输的可用地址
    user: 当前用户对象，用于查询相关交易
    """
    # 生成 SEED_B 的地址集
    seed_b_wallets = generate_btc_keypairs_from_seed(SEED_B, MAX_ADDR_LENGTH)
    seed_b_addrs = [w[2] for w in seed_b_wallets]

    # 获取用户所有交易，提取所有接收方地址
    user_txs = blockchain.get_all_transactions(user)
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
    user_txs = blockchain.get_all_transactions(user)
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
    user_txs = blockchain.get_all_transactions(user)
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
    user_txs = blockchain.get_all_transactions(user)
    if not user_txs:
        return None

    # 找到所有 SEED_B 地址中被使用的地址
    used_wallets = [w for w in seed_b_wallets if any(tx["to"] == w[2] for tx in user_txs if tx['from'] != 'SYSTEM')]
    return used_wallets[-1] if used_wallets else None


def get_public_key_from_address(address):
    """
    根据钱包地址查找公钥
    :param address: 钱包地址
    :return: 公钥字符串或 None
    """
    if address == "SYSTEM":
        return SYSTEM_PUBLIC_KEY
    else:
        users = User.load_all()
        for user in users.keys():
            for wallet in users.get(user, {}).get("wallets", {}):
                if wallet.get("address") == address:
                    return wallet.get("public")
    return None
