from sender import Sender
from receiver import Receiver
from utils.log import log

if __name__ == "__main__":
    sender = Sender(init_sk=1733)
    receiver = Receiver(init_sk=1733)

    msg = "这是一个测试"
    # log("INFO", f"原始消息: {msg}")

    txs = sender.embed_message(msg)
    # log("INFO",f"生成的携密交易数: {len(txs)}")

    recovered = receiver.extract_message(txs)
    # log("INFO",f"解密恢复消息: {recovered}")
