from message_transfer import Sender, Receiver

# 初始化发送者/接收者
sender = Sender(init_sk=123)
receiver = Receiver(init_sk=123)

# 嵌入消息
message = "Hello, this is a secret message!"
txs = sender.embed_message(message)
print(txs)

# 接收者提取消息
extracted = receiver.extract_message(txs)
print("接收者提取的消息:", extracted)
