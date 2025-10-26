from tqdm import tqdm
from blockchain import blockchain
from config import SEED_A, MAX_ADDR_LENGTH, SEED_B, SYSTEM_PUBLIC_KEY
from users.user import User
from utils.utils_crypto import generate_btc_keypairs_from_seed


def init_walltes_from_seed(system, user, seed, num_wallets):
    wallets = generate_btc_keypairs_from_seed(seed, num_wallets)
    for i, (priv, pub, addr) in enumerate(tqdm(wallets, desc="初始化钱包", unit="个"), start=1):
        created, _, _ = system.add_custom_wallet(user, priv, pub, addr)
    return wallets


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


def get_wallet_from_address(address):
    """
    根据钱包地址查找钱包信息
    :param address: 钱包地址
    :return: 钱包信息字典或 None
    """
    users = User.load_all()
    for user in users.keys():
        for wallet in users.get(user, {}).get("wallets", {}):
            if wallet.get("address") == address:
                return wallet
