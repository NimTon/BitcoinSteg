from blockchain import Blockchain
from message_transfer import Sender, Receiver

# 创建区块链
bc = Blockchain()
if not bc.chain:
    bc.create_genesis_block()

# Sender 发送消息
sender = Sender(sk_init=123)
message = "Hello, this message is embedded in blockchain!"
sender.send_message(message, bc)

# Receiver 提取消息
receiver = Receiver(sk_init=123)
received_msg = receiver.receive_message(bc)
print("接收者提取的消息:", received_msg)
