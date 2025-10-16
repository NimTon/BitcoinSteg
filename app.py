from flask import Flask, request, jsonify
from flask_cors import CORS
from blockchain.blockchain import bc
from utils.crypto_utils import verify_signature, get_public_key_from_address
from system.crypto_system import CryptoSystem
import uuid

app = Flask(__name__)
CORS(app)
crypto = CryptoSystem()

# 简单 Token 存储
tokens = {}


# ================= 用户注册 =================
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    success, msg = crypto.register_user(username, password)
    return jsonify({"success": success, "message": msg})


# ================= 用户登录 =================
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user, msg = crypto.login_user(username, password)
    if user:
        token = str(uuid.uuid4())
        tokens[token] = username
        return jsonify({"success": True, "token": token, "message": msg})
    return jsonify({"success": False, "message": msg})


# ================= Token 验证装饰器 =================
def token_required(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or token not in tokens:
            return jsonify({"success": False, "message": "无效Token"}), 401
        return f(tokens[token], *args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# ================= 钱包管理 =================
@app.route("/api/wallets", methods=["GET", "POST", "DELETE"])
@token_required
def wallets(username):
    """
    钱包管理接口：
      GET    获取用户所有钱包及余额
      POST   新增一个钱包
      DELETE 删除一个钱包（余额需为0）
    """
    # 重新实例化用户对象
    user, _ = crypto.login_user(username, crypto.users[username]["password"])

    # 查询钱包列表
    if request.method == "GET":
        ok, msg, wallets = crypto.list_wallets(username)
        return jsonify({"success": ok, "message": msg, "wallets": wallets})

    # 新增钱包
    elif request.method == "POST":
        ok, msg, new_wallet = crypto.add_wallet(username)
        if ok:
            return jsonify({"success": True, "message": msg, "wallet": new_wallet})
        else:
            return jsonify({"success": False, "message": msg}), 400

    # 删除钱包
    elif request.method == "DELETE":
        data = request.json
        address = data.get("address")
        if not address:
            return jsonify({"success": False, "message": "缺少地址参数"}), 400

        ok, msg = crypto.delete_wallet(username, address)
        if ok:
            return jsonify({"success": True, "message": msg})
        else:
            return jsonify({"success": False, "message": msg}), 400


@app.route("/api/wallets/<address>", methods=["GET"])
@token_required
def get_wallet_by_address(username, address):
    """
    查询指定钱包详情（含余额）
    """
    ok, msg, wallets = crypto.list_wallets(username)
    if not ok:
        return jsonify({"success": False, "message": msg}), 400

    wallet = next((w for w in wallets if w["address"] == address), None)
    if not wallet:
        return jsonify({"success": False, "message": "钱包不存在"}), 404

    return jsonify({"success": True, "wallet": wallet})


# ================= 查询余额 =================
@app.route("/api/balance/<address>", methods=["GET"])
def balance(address):
    bal = crypto.blockchain.get_balance(address)
    return jsonify({"address": address, "balance": bal})


# ================= 转账 =================
@app.route("/api/transfer", methods=["POST"])
@token_required
def transfer(username):
    data = request.json
    from_addr = data.get("from_addr")
    to_addr = data.get("to_addr")
    amount = data.get("amount")

    user, _ = crypto.login_user(username, crypto.users[username]["password"])
    success, msg, tx_hash = crypto.transfer(user, from_addr, to_addr, amount)
    return jsonify({"success": success, "message": msg, "tx_hash": tx_hash})


# ================= Faucet 测试币领取 =================
@app.route("/api/faucet", methods=["POST"])
@token_required
def faucet_route(username):
    """
    用户领取测试币接口
    POST 参数:
      - address: 钱包地址
      - amount: 发币数量
    """
    data = request.json
    address = data.get("address")
    amount = data.get("amount")

    # 简单验证
    if not address or not amount or float(amount) <= 0:
        return jsonify({"success": False, "message": "地址或金额无效"}), 400

    # 调用系统的 faucet 函数
    try:
        crypto.blockchain.faucet(address, float(amount))
        return jsonify({"success": True, "message": f"{amount} 测试币已发送到 {address}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route('/api/user/<address>/transactions', methods=['GET'])
def get_user_transactions(address):
    """
    获取某个用户地址的交易历史
    """
    history = []
    for block in bc.load_chain():
        for tx in block['transactions']:
            if tx['from'] == address or tx['to'] == address:
                history.append({
                    "from": tx['from'],
                    "to": tx['to'],
                    "amount": tx['amount'],
                    "signature": tx['signature'],
                    "hash": tx.get('hash')
                })
    return jsonify(history)


@app.route("/api/verify_transaction", methods=["POST"])
def verify_transaction():
    """
    验证选中交易的签名
    body: { "transaction": {...} }
    """
    data = request.json
    tx = data.get("transaction")
    if not tx:
        return jsonify({"success": False, "message": "交易数据缺失"}), 400

    from_addr = tx.get("from")
    from_pubkey = get_public_key_from_address(from_addr)

    valid = verify_signature(
        public_key_hex=from_pubkey,  # 使用发送方公钥
        message=f"{tx['from']}->{tx['to']}:{tx['amount']}",  # 原文消息
        signature_hex=tx['signature']
    )

    return jsonify({"success": valid})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
