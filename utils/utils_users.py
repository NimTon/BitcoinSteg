from users.user import User


def get_user_from_wallet(address=None, privkey_hex=None, pubkey_hex=None):
    users = User.load_all()
    for username in users.keys():
        for wallet in users.get(username, {}).get("wallets", {}):
            if wallet.get("address") == address or wallet.get("private") == privkey_hex or wallet.get("public") == pubkey_hex:
                return User.load(username)
    return None
