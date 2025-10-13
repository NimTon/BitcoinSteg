class WalletManager:
    def __init__(self, blockchain):
        self.blockchain = blockchain

    def get_pubkeys_by_address(self, address):
        """
        根据钱包地址获取对应公钥
        """
        from_pubkeys = set()
        to_pubkeys = set()

        for block in self.blockchain.chain:
            for tx in block['transactions']:
                if tx['from'] == address and tx.get('from_pubkey'):
                    from_pubkeys.add(tx['from_pubkey'])
                if tx['to'] == address and tx.get('to_pubkey'):
                    to_pubkeys.add(tx['to_pubkey'])

        return {
            "from_pubkeys": list(from_pubkeys),
            "to_pubkeys": list(to_pubkeys)
        }