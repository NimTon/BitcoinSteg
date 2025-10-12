from typing import Optional
from utils.utils import *
from config import CONFIG
from utils.log import log, log_multiline

class Receiver:
    def __init__(self, init_sk: int, log_path: Optional[str] = None):
        self.sk_init = init_sk
        self.AES_KEY = CONFIG["AES_KEY"]
        self.n = CONFIG["n"]
        self.LE = CONFIG["LE"]
        self.TERMINATOR = CONFIG["TERMINATOR"]
        self.log_path = log_path

        log("INFO", f"[RECEIVER] Receiver initialized with parameters:", log_path)
        log_multiline("INFO",
                      f"[RECEIVER] AES_KEY: {self.AES_KEY}",
                      f"[RECEIVER] n: {self.n}",
                      f"[RECEIVER] LE (嵌入比特长度): {self.LE}",
                      f"[RECEIVER] TERMINATOR: {self.TERMINATOR}",
                      f"[RECEIVER] init_sk: {self.sk_init}",
                      log_path=log_path)

    def generate_address(self, sk: int) -> str:
        """根据私钥生成接收地址"""
        addr = hashlib.md5(str(sk).encode()).hexdigest()[:16]
        log("INFO", f"[RECEIVER] Generated address {addr} from sk={sk}", self.log_path)
        return addr

    def extract_message(self, txs: list) -> str:
        """从交易列表中提取加密信息，支持 1+3 方案"""
        bits = ""
        log("INFO", f"[RECEIVER] 开始提取消息，共 {len(txs)} 笔交易", self.log_path)
        for i, tx in enumerate(sorted(txs, key=lambda x: x["idx"])):
            h = tx.get("hash", "")
            if not h:
                log("WARNING", f"[RECEIVER] 交易 {i} 无哈希值，跳过", self.log_path)
                continue
            embedded_bits = extract_lsb_bits(h, self.LE)
            bits += embedded_bits
            log("INFO", f"[RECEIVER] 从交易 {i} 提取 {len(embedded_bits)} 比特: {embedded_bits}, 累计: {bits}", self.log_path)

            # Step 1️⃣ 检测终止符，停止提取
            if self.TERMINATOR in bits:
                end_index = bits.find(self.TERMINATOR)
                bits = bits[:end_index]
                log("INFO", f"[RECEIVER] 检测到终止符，截取后比特串: {bits}", self.log_path)
                break

        if not bits:
            log("FAIL", "[RECEIVER] 未提取到任何比特信息！")
            return ""

        log("INFO", f"[RECEIVER] 提取完成，原始比特串: {bits}", self.log_path)

        # Step 2️⃣ 4-bit -> HEX
        cipher_hex = ""
        for i in range(0, len(bits), 4):
            block = bits[i:i + 4]
            if len(block) < 4:  # 补0以保证长度
                block = block.ljust(4, '0')
            hex_char = hex(int(block, 2))[2:]
            cipher_hex += hex_char
        log("INFO", f"[RECEIVER] 转换为十六进制: {cipher_hex}", self.log_path)

        try:
            message = aes_decrypt(cipher_hex, self.AES_KEY)
            log("SUCCESS", f"[RECEIVER] 成功解密消息: {message}")
            return message
        except Exception as e:
            log("FAIL", f"[RECEIVER] 解密失败: {e}")
            return ""
