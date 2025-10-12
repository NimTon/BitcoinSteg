class Transaction:
    """
    交易类，用于表示区块链中的一笔交易
    """
    
    def __init__(self, from_addr, to_addr, amount, signature):
        """
        初始化交易对象
        
        Args:
            from_addr: 发送方地址
            to_addr: 接收方地址
            amount: 交易金额
            signature: 交易签名
        """
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        """
        将交易对象转换为字典格式
        
        Returns:
            dict: 包含交易信息的字典
        """
        return {
            'from': self.from_addr,
            'to': self.to_addr,
            'amount': self.amount,
            'signature': self.signature
        }
