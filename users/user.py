from utils.crypto_utils import generate_btc_keypair

class User:
    """
    用户类，用于管理用户信息和钱包
    """
    def __init__(self, username, password):
        """
        初始化用户对象
        
        Args:
            username (str): 用户名
            password (str): 密码
        """
        self.username = username
        self.password = password
        self.wallets = []  # 钱包列表，每个元素包含私钥、公钥和地址

    def add_wallet(self):
        """
        为用户添加一个新的钱包
        
        Returns:
            str: 新生成的钱包地址
        """
        # 生成密钥对和地址
        private, public, address = generate_btc_keypair()
        # 将钱包信息添加到用户的钱包列表中
        self.wallets.append({'private': private, 'public': public, 'address': address})
        return address

    def get_balance(self, blockchain):
        """
        获取用户所有钱包的总余额
        
        Args:
            blockchain: 区块链对象，用于查询余额
            
        Returns:
            float: 用户所有钱包的总余额
        """
        balance = 0
        # 遍历用户的所有钱包
        for wallet in self.wallets:
            addr = wallet['address']
            # 累加每个钱包的余额
            balance += blockchain.get_balance(addr)
        return balance
