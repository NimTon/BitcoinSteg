import os

from system.crypto_system import CryptoSystem
from blockchain.transaction import Transaction

def faucet(blockchain, address, amount=50):
    tx = Transaction("SYSTEM", address, amount, "SYSTEM")
    blockchain.add_block([tx])
    print(f"{amount} 币已发放到 {address}")

os.makedirs('data', exist_ok=True)

if __name__ == "__main__":
    system = CryptoSystem()

    # 注册用户
    system.register_user("alice", "123456")
    system.register_user("bob", "abcdef")

    # 登录用户
    alice, _ = system.login_user("alice", "123456")
    bob, _ = system.login_user("bob", "abcdef")

    # 打印钱包地址
    print("Alice wallets:", [w['address'] for w in alice.wallets])
    print("Bob wallets:", [w['address'] for w in bob.wallets])

    # 给 Alice 和 Bob 发币
    # faucet(system.blockchain, alice.wallets[0]['address'], 100)
    # faucet(system.blockchain, bob.wallets[0]['address'], 50)

    # 查看余额
    print("Alice balance:", alice.get_balance(system.blockchain))
    print("Bob balance:", bob.get_balance(system.blockchain))

    # Alice 给 Bob 转账 10
    from_addr = alice.wallets[0]['address']
    to_addr = bob.wallets[0]['address']
    success, msg = system.transfer(alice, from_addr, to_addr, 10)
    print(success, msg)

    # 打印余额
    print("Alice balance:", alice.get_balance(system.blockchain))
    print("Bob balance:", bob.get_balance(system.blockchain))
