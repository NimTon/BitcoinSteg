import binascii
import traceback

from transaction import Transaction
from utils.crypto_utils import aes_encrypt, aes_decrypt, key_expand, CONFIG, extract_lsb_bits, random_amount
from utils.log import log, log_multiline, LogColors


class Sender:
    def __init__(self, sk_init):
        self.sk_init = sk_init

    def generate_address(self, sk):
        import hashlib
        return hashlib.md5(str(sk).encode()).hexdigest()[:16]

    def send_message(self, message, blockchain):
        log("INFO", f"开始发送消息: {message}")
        # AES 加密 + 终止符
        encrypted = aes_encrypt(message, CONFIG["AES_KEY"])
        log("INFO", f"消息加密完成，长度: {len(encrypted)}, 内容: {encrypted}")
        bits = "".join([bin(int(x, 16))[2:].zfill(4) for x in encrypted]) + CONFIG["TERMINATOR"]
        log("INFO", f"消息被编码为 {len(bits)} 位二进制，内容: {bits}")
        chunks = [bits[i:i + CONFIG["LE"]] for i in range(0, len(bits), CONFIG["LE"])]
        if len(chunks[-1]) < CONFIG["LE"]:
            chunks[-1] += "0" * (CONFIG["LE"] - len(chunks[-1]))

        log("INFO", f"消息被分割为 {len(chunks)} 个数据块")

        txs = []
        for idx, sub_bits in enumerate(chunks):
            log("INFO", f"处理第 {idx+1}/{len(chunks)} 个数据块")
            sk = key_expand(self.sk_init + idx, CONFIG["AES_KEY"], CONFIG["n"])
            sender_addr = self.generate_address(sk)
            receiver_addr = self.generate_address(sk + 1)

            # 采样金额直到 LSB 匹配
            attempts = 0
            while True:
                attempts += 1
                amount = random_amount()
                tx = Transaction(sender_addr, receiver_addr, amount)
                extracted_bits = extract_lsb_bits(tx.hash, CONFIG["LE"])
                if extracted_bits == sub_bits:
                    txs.append(tx)
                    log("SUCCESS", f"数据块 {idx+1} 匹配成功，尝试次数: {attempts}")
                    break

        # 发送：打包进区块
        blockchain.add_block(txs)
        log("INFO", f"消息发送完成，共 {len(txs)} 笔交易")
        return txs


class Receiver:
    def __init__(self, sk_init):
        self.sk_init = sk_init

    def generate_address(self, sk):
        import hashlib
        return hashlib.md5(str(sk).encode()).hexdigest()[:16]

    def receive_message(self, blockchain):
        log("INFO", "开始接收消息")
        bits = ""
        idx = 0
        while True:
            sk = key_expand(self.sk_init + idx, CONFIG["AES_KEY"], CONFIG["n"])
            expected_sender = self.generate_address(sk)
            expected_receiver = self.generate_address(sk + 1)

            tx_found = False
            for block in blockchain.chain:
                for tx in block.transactions:
                    if tx.sender == expected_sender and tx.receiver == expected_receiver:
                        extracted_bits = extract_lsb_bits(tx.hash, CONFIG["LE"])
                        bits += extracted_bits
                        log("INFO", f"找到数据块 {idx+1}, 提取位: {extracted_bits}")
                        tx_found = True
                        break
                if tx_found:
                    break

            if not tx_found:
                log("WARNING", f"未找到数据块 {idx+1}，接收结束")
                break

            if CONFIG["TERMINATOR"] in bits:
                original_bits = bits
                bits = bits[:bits.find(CONFIG["TERMINATOR"])]
                log("INFO", f"检测到终止符，原始位: {original_bits}, 截断后: {bits}")
                break
            idx += 1

        # bits -> HEX -> AES解密

        log("INFO", f"接收到的位序列: {bits}")
        cipher_hex = ""
        for i in range(0, len(bits), 4):
            block = bits[i:i + 4]
            if len(block) < 4:  # 补0以保证长度
                block = block.ljust(4, '0')
            hex_char = hex(int(block, 2))[2:]
            cipher_hex += hex_char
        log("INFO", f"开始解密，十六进制数据: {cipher_hex}")
        try:
            message = aes_decrypt(cipher_hex, CONFIG["AES_KEY"])
            log("SUCCESS", f"消息解密成功: {message}")
            return message
        except Exception as e:
            log("FAIL", f"消息解密失败: {str(e)}")
            traceback.print_exc()
            return ""
