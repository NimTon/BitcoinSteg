import time
import hashlib
from utils.utils import *
from config import CONFIG
from utils.log import log, log_multiline


class Sender:
    def __init__(self, init_sk: int, log_path: str = None):
        self.sk_init = init_sk
        self.AES_KEY = CONFIG["AES_KEY"]
        self.n = CONFIG["n"]
        self.LE = CONFIG["LE"]
        self.TERMINATOR = CONFIG["TERMINATOR"]
        self.sent_txs = []  # 存储发布的携密交易
        self.log_path = log_path

        log("INFO", f"[SENDER] 初始化 Sender 实例：初始私钥={self.sk_init}, AES_KEY={self.AES_KEY}, n={self.n}", self.log_path)

    def generate_address(self, sk: int) -> str:
        """模拟ECC地址生成"""
        addr = hashlib.md5(str(sk).encode()).hexdigest()[:16]
        log("INFO", f"[SENDER] 生成地址：sk={sk} -> address={addr}", self.log_path)
        return addr

    def embed_message(self, message: str):
        """核心流程：将密文嵌入交易哈希，采用 1+3 方案"""
        log("INFO", f"[SENDER] 开始嵌入消息: \"{message}\"", self.log_path)
        start = time.time()

        # Step 1️⃣ AES加密消息 + 终止符
        encrypted = aes_encrypt(message, self.AES_KEY)
        bits = "".join([bin(int(x, 16))[2:].zfill(4) for x in encrypted]) + self.TERMINATOR
        log_multiline(
            "INFO",
            f"[SENDER] AES 加密结果: {encrypted}",
            f"[SENDER] 总比特长度: {len(bits)} bits",
            f"[SENDER] 终止符: {self.TERMINATOR}",
            log_path=self.log_path
        )

        # Step 2️⃣ 拆分为每笔交易携密长度 LE 的小块
        chunks = [bits[i:i + self.LE] for i in range(0, len(bits), self.LE)]
        # Step 2a️⃣ 最后一块不足 LE 用 0 填充
        if len(chunks[-1]) < self.LE:
            chunks[-1] += "0" * (self.LE - len(chunks[-1]))

        log("INFO", f"[SENDER] 消息分块完成，共 {len(chunks)} 个交易块 (每块 {self.LE} bits)", self.log_path)

        # Step 3️⃣ 针对每个比特块生成交易
        for idx, sub_bits in enumerate(chunks):
            log("INFO", f"[SENDER] 正在处理第 {idx + 1}/{len(chunks)} 个块: {sub_bits}")

            # 密钥拓展：生成新的私钥
            sk = key_expand(self.sk_init + idx, self.AES_KEY, self.n)
            sender_addr = self.generate_address(sk)
            receiver_addr = self.generate_address(sk + 1)

            # Step 4️⃣ 采样金额直到匹配目标哈希
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
                    log("WARNING", f"[SENDER] 第 {sample_count} 次采样仍未匹配，继续搜索... 当前哈希: {h}, 提取位: {extracted_bits}, 目标位: {sub_bits}")

        end = time.time()
        log("SUCCESS", f"[SENDER] 携密交易生成完毕，共 {len(self.sent_txs)} 笔，用时 {end - start:.2f}s")
        return self.sent_txs

