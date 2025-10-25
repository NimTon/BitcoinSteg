from ecdsa import VerifyingKey, SECP256k1


def verify_signature(public_key_hex, message, signature_hex):
    """
    验证消息签名是否有效
    参数:
        public_key_hex (str): 公钥的十六进制字符串
        message (str): 原始消息
        signature_hex (str): 签名的十六进制字符串
    返回:
        bool: 签名验证结果，True表示有效，False表示无效
    """
    # 从十六进制字符串恢复公钥
    vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
    try:
        # 验证签名
        return vk.verify(bytes.fromhex(signature_hex), message.encode())
    except:
        # 验证失败返回False
        return False
