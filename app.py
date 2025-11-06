import json
import os
import traceback
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from blockchain import blockchain, transaction_pool
from blockchain.miner import Miner
from config import MAX_ADDR_LENGTH, MATCH_BITS
from utils.utils import allowed_file, parse_seed
from utils.utils_crypto import generate_btc_keypairs_from_seed
from utils.utils_blockchain import verify_signature
from users.user import User
from system import system
import uuid
from utils import utils_encrypt_tx, utils_encrypt_address, utils_encrypt_vblocce
from utils.utils_wallets import get_public_key_from_address

app = Flask(__name__)
CORS(app)
FRONTEND_DIST = "frontend"
# 简单 Token 存储
tokens = {}


# -------- 前端路由 --------
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_vue(path):
    full_path = os.path.join(FRONTEND_DIST, path)
    if path and os.path.exists(full_path) and not os.path.isdir(full_path):
        # 静态资源存在，直接返回
        return send_from_directory(FRONTEND_DIST, path)
    else:
        # 不存在文件，返回 index.html，交给 Vue Router 处理
        return send_from_directory(FRONTEND_DIST, 'index.html')


# ================= 用户注册 =================
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    success, msg = system.register_user(username, password)
    return jsonify({"success": success, "message": msg})


# ================= 用户登录 =================
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user, msg = system.login_user(username, password)
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
    # 实例化用户对象
    user = User.load(username)

    # 查询钱包列表
    if request.method == "GET":
        ok, msg, wallets = system.list_wallets(user)
        wallets = wallets[::-1][:20]
        return jsonify({"success": ok, "message": msg, "wallets": wallets})

    # 新增钱包
    elif request.method == "POST":
        ok, msg, new_wallet = system.add_wallet(user)
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

        ok, msg = system.delete_wallet(user, address)
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
    ok, msg, wallets = system.list_wallets(username)
    if not ok:
        return jsonify({"success": False, "message": msg}), 400

    wallet = next((w for w in wallets if w["address"] == address), None)
    if not wallet:
        return jsonify({"success": False, "message": "钱包不存在"}), 404

    return jsonify({"success": True, "wallet": wallet})


# ================= 查询余额 =================
@app.route("/api/balance/<address>", methods=["GET"])
def balance(address):
    bal = system.blockchain.get_balance(address)
    return jsonify({"address": address, "balance": bal})


# ================= 转账 =================
@app.route("/api/transfer", methods=["POST"])
def transfer():
    data = request.json
    from_addr = data.get("from_addr")
    to_addr = data.get("to_addr")
    amount = data.get("amount")
    success, msg, tx_hash = system.transfer(from_addr, to_addr, amount)
    return jsonify({"success": success, "message": msg, "tx_hash": tx_hash})


@app.route('/api/address/<address>/transactions', methods=['GET'])
def get_user_transactions(address):
    """
    获取某个用户地址的交易历史
    """
    history = []
    for block in blockchain.load_chain():
        for tx in block['transactions']:
            if tx['from'] == address or tx['to'] == address:
                history.append({
                    "from": tx['from'],
                    "to": tx['to'],
                    "amount": tx['amount'],
                    "signature": tx['signature'],
                    "hash": tx['hash'],
                    "timestamp": block['timestamp'],
                })
    history = history[::-1][:20]
    return jsonify(history)


@app.route('/api/username/<username>/transactions', methods=['GET'])
def get_user_transactions_by_username(username):
    """
    获取某个用户名的交易历史（包含该用户所有钱包的交易）
    """
    user = User.load(username)
    related_txs = blockchain.get_all_transactions(user)
    related_txs = related_txs[::-1][:20]
    if not related_txs:
        return jsonify([])  # 用户没有钱包，返回空列表

    return jsonify(related_txs)


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
    if from_addr == "SYSTEM":
        miner_address = tx.get('to')
        reward = tx.get('amount')
        block_index = tx.get('block_height')
        message = f"{miner_address}:{reward}:{block_index}"
    else:
        message = f"{tx['from']}->{tx['to']}:{tx['amount']}"
    valid = verify_signature(
        public_key_hex=from_pubkey,  # 使用发送方公钥
        message=message,  # 原文消息
        signature_hex=tx['signature']
    )
    return jsonify({"success": valid})


@app.route('/api/generate_wallet', methods=['POST'])
def generate_wallet():
    """根据种子生成钱包并注入测试资金"""
    data = request.get_json()
    username = data.get("username")
    seed = data.get("seed")
    count = int(data.get("count", 1))

    wallets = generate_btc_keypairs_from_seed(seed, count)
    for private_key, public_key, address in wallets:
        system.add_custom_wallet(username, private_key, public_key, address)
        blockchain.faucet(address, 1000)
    return jsonify({"wallets": [w[2] for w in wallets]})


@app.route('/api/address/<address>/send_message', methods=['POST'])
def send_message(address):
    """加密并发送消息"""
    data = request.get_json()
    message = data.get("message")
    seed = parse_seed(data.get("seed"))
    algorithm = data.get('algorithm')
    if not message:
        return jsonify({"error": "消息不能为空"}), 400
    if algorithm == 'A':
        if utils_encrypt_tx.encrypt_and_send(system, from_address=address, message=message, seed=seed):
            return jsonify({"message": "消息加密并发送成功"})
        else:
            return jsonify({"error": "消息加密并发送失败"}), 500
    elif algorithm == 'B':
        if utils_encrypt_address.encrypt_and_send(system, from_address=address, message=message, seed=seed):
            return jsonify({"message": "消息发送成功"})
        else:
            return jsonify({"error": "消息发送失败"}), 500
    elif algorithm == 'C':
        if utils_encrypt_vblocce.encrypt_and_send(system, from_address=address, message=message, seed=seed):
            return jsonify({"message": "消息发送成功"})
        else:
            return jsonify({"error": "消息发送失败"}), 500
    else:
        return jsonify({"error": "未知的加密算法"}), 400


@app.route('/api/decrypt_message', methods=['GET'])
def decrypt_message():
    """解密交易中的消息"""
    seed = request.args.get('seed')
    algorithm = request.args.get('algorithm')
    if not seed:
        return jsonify({'error': '缺少 seed 参数'}), 400
    seed = parse_seed(seed)
    if algorithm == 'A':
        decoded_msg = utils_encrypt_tx.decrypt_from_transactions(seed=seed)
        if not decoded_msg:
            return jsonify({"message": "没有待解密消息"})
        return jsonify({"decoded_message": decoded_msg})
    elif algorithm == 'B':
        decoded_msg = utils_encrypt_address.decrypt_from_transactions(seed=seed)
        if not decoded_msg:
            return jsonify({"message": "没有待解密消息"})
        return jsonify({"decoded_message": decoded_msg})
    elif algorithm == 'C':
        decoded_msg = utils_encrypt_vblocce.decrypt_from_transactions(seed=seed)
        if not decoded_msg:
            return jsonify({"message": "没有待解密消息"})
        return jsonify({"decoded_message": decoded_msg})
    return jsonify({"error": "未知的解密算法"}), 400


@app.route('/api/address/<address>/mine', methods=['POST'])
def mine_by_address(address):
    miner = Miner(blockchain, transaction_pool, miner_address=address)
    miner.mine(max_txs_per_block=999)
    return jsonify({"message": "挖矿成功"})


@app.route('/api/reset_system', methods=['POST'])
def reset_system():
    """
    重置所有交易数据
    """
    blockchain.clear_chain()
    transaction_pool.clear_pool()
    return jsonify({"message": "系统已重置"})


# 捕获所有未被处理的异常（全局）
@app.errorhandler(Exception)
def handle_exception(e):
    # 打印详细堆栈信息到控制台
    error_info = traceback.format_exc()
    app.logger.error(f"Exception in {request.path}:\n{error_info}")

    # 返回统一的 JSON 格式
    return jsonify({
        "code": 500,
        "message": str(e)
    }), 500


# 记录所有非200响应
@app.after_request
def log_response(response):
    if response.status_code != 200:
        data_text = response.get_data(as_text=True)
        try:
            data_dict = json.loads(data_text)
            message = json.dumps(data_dict, ensure_ascii=False)
        except Exception:
            message = data_text
        app.logger.warning(
            f"{response.status_code} {request.method} {request.path} → {message}"
        )
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
