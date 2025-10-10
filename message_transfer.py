import time, hashlib
from utils.crypto_utils import *
from typing import Optional

class Sender:
    def __init__(self, init_sk: int, log_path: Optional[str] = None):
        self.sk_init = init_sk
        self.AES_KEY = CONFIG["AES_KEY"]
        self.n = CONFIG["n"]
        self.LE = CONFIG["LE"]
        self.TERMINATOR = CONFIG["TERMINATOR"]
        self.sent_txs = []  # 存储发布的携密交易
        self.log_path = log_path

    def log(self, level, msg):
        print(f"[SENDER][{level}] {msg}" if not self.log_path else f"{msg}")

    def generate_address(self, sk: int) -> str:
        addr = hashlib.md5(str(sk).encode()).hexdigest()[:16]
        self.log("INFO", f"生成地址：sk={sk} -> address={addr}")
        return addr

    def embed_message(self, message: str):
        self.log("INFO", f"开始嵌入消息: \"{message}\"")
        start = time.time()

        # Step 1️⃣ AES加密消息 + 终止符
        encrypted = aes_encrypt(message, self.AES_KEY)
        bits = "".join([bin(int(x,16))[2:].zfill(4) for x in encrypted]) + self.TERMINATOR

        # Step 2️⃣ 拆分为每笔交易携密长度 LE 的小块
        chunks = [bits[i:i+self.LE] for i in range(0,len(bits),self.LE)]
        if len(chunks[-1]) < self.LE:
            chunks[-1] += "0" * (self.LE - len(chunks[-1]))

        self.log("INFO", f"消息分块完成，共 {len(chunks)} 个交易块，每块 {self.LE} bits")

        # Step 3️⃣ 针对每个比特块生成交易
        for idx, sub_bits in enumerate(chunks):
            self.log("INFO", f"处理第 {idx+1}/{len(chunks)} 个块: {sub_bits}")
            sk = key_expand(self.sk_init + idx, self.AES_KEY, self.n)
            sender_addr = self.generate_address(sk)
            receiver_addr = self.generate_address(sk + 1)

            sample_count = 0
            while True:
                amount = random_amount()
                h = tx_hash(sender_addr, receiver_addr, amount)
                sample_count += 1
                extracted_bits = extract_lsb_bits(h, self.LE)
                if extracted_bits == sub_bits:
                    self.sent_txs.append({
                        "idx": idx,
                        "sender": sender_addr,
                        "receiver": receiver_addr,
                        "amount": amount,
                        "hash": h,
                        "bits": sub_bits,
                        "samples": sample_count
                    })
                    break
                elif sample_count % 100 == 0:
                    self.log("WARNING", f"第 {sample_count} 次采样仍未匹配，继续搜索...")

        end = time.time()
        self.log("SUCCESS", f"携密交易生成完毕，共 {len(self.sent_txs)} 笔，用时 {end-start:.2f}s")
        return self.sent_txs


class Receiver:
    def __init__(self, init_sk: int, log_path: Optional[str] = None):
        self.sk_init = init_sk
        self.AES_KEY = CONFIG["AES_KEY"]
        self.n = CONFIG["n"]
        self.LE = CONFIG["LE"]
        self.TERMINATOR = CONFIG["TERMINATOR"]
        self.log_path = log_path

    def log(self, level, msg):
        print(f"[RECEIVER][{level}] {msg}" if not self.log_path else f"{msg}")

    def generate_address(self, sk: int) -> str:
        addr = hashlib.md5(str(sk).encode()).hexdigest()[:16]
        self.log("INFO", f"生成地址：sk={sk} -> address={addr}")
        return addr

    def extract_message(self, txs: list) -> str:
        bits = ""
        self.log("INFO", f"开始提取消息，共 {len(txs)} 笔交易")
        for i, tx in enumerate(sorted(txs, key=lambda x:x["idx"])):
            h = tx.get("hash", "")
            if not h:
                continue
            embedded_bits = extract_lsb_bits(h, self.LE)
            bits += embedded_bits
            if self.TERMINATOR in bits:
                end_index = bits.find(self.TERMINATOR)
                bits = bits[:end_index]
                break

        if not bits:
            self.log("FAIL", "未提取到任何比特信息！")
            return ""

        # bits -> HEX
        cipher_hex = ""
        for i in range(0, len(bits), 4):
            block = bits[i:i+4].ljust(4,'0')
            cipher_hex += hex(int(block,2))[2:]

        try:
            message = aes_decrypt(cipher_hex, self.AES_KEY)
            self.log("SUCCESS", f"成功解密消息: {message}")
            return message
        except Exception as e:
            self.log("FAIL", f"解密失败: {e}")
            return ""
