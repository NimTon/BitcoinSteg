from utils.crypto_utils import generate_keypair

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.wallets = []  # [{'private':..., 'public':..., 'address':...}]

    def add_wallet(self):
        private, public, address = generate_keypair()
        self.wallets.append({'private': private, 'public': public, 'address': address})
        return address

    def get_balance(self, blockchain):
        balance = 0
        for wallet in self.wallets:
            addr = wallet['address']
            balance += blockchain.get_balance(addr)
        return balance
