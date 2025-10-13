import os
from blockchain.blockchain import bc
from system.crypto_system import CryptoSystem
from blockchain.transaction import Transaction



os.makedirs('data', exist_ok=True)

if __name__ == "__main__":
    system = CryptoSystem()

    # 注册用户
    system.register_user("123", "123")
    system.register_user("321", "321")

    # 登录用户
    alice, _ = system.login_user("123", "123")
    bob, _ = system.login_user("321", "321")

    # 打印钱包地址
    print("123 wallets:", [w['address'] for w in alice.wallets])
    print("321 wallets:", [w['address'] for w in bob.wallets])

    # 给 Alice 和 Bob 发币
    bc.faucet(alice.wallets[0]['address'], 100)
    bc.faucet(bob.wallets[0]['address'], 50)

    # 查看余额
    print("123 balance:", alice.get_balance(system.blockchain))
    print("321 balance:", bob.get_balance(system.blockchain))

    # Alice 给 Bob 转账 10
    from_addr = alice.wallets[0]['address']
    to_addr = bob.wallets[0]['address']
    success, msg, tx_hash = system.transfer(alice, from_addr, to_addr, 10)
    print(success, msg, tx_hash)

    # 打印余额
    print("123 balance:", alice.get_balance(system.blockchain))
    print("321 balance:", bob.get_balance(system.blockchain))
