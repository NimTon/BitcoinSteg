import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from blockchain.blockchain import bc
from config import MAX_ADDR_LENGTH, MATCH_BITS
from utils.utils_crypto import verify_signature, get_public_key_from_address, generate_btc_keypairs_from_seed
from system.crypto_system import CryptoSystem
import uuid
from utils.utils_encrypt_tx import encrypt_and_send, decrypt_from_transactions
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)
crypto = CryptoSystem()
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
    success, msg, tx_hash, block_hash = crypto.transfer(user, from_addr, to_addr, amount)
    return jsonify({"success": success, "message": msg, "tx_hash": tx_hash, "block_hash": block_hash})


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


@app.route('/api/address/<address>/transactions', methods=['GET'])
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


@app.route('/api/username/<username>/transactions', methods=['GET'])
def get_user_transactions_by_username(username):
    """
    获取某个用户名的交易历史（包含该用户所有钱包的交易）
    """
    user, _ = crypto.login_user(username, crypto.users[username]["password"])
    related_txs = bc.get_all_transactions(user)
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

    valid = verify_signature(
        public_key_hex=from_pubkey,  # 使用发送方公钥
        message=f"{tx['from']}->{tx['to']}:{tx['amount']}",  # 原文消息
        signature_hex=tx['signature']
    )

    return jsonify({"success": valid})


@app.route('/api/generate_wallet', methods=['POST'])
def generate_wallet():
    """根据种子生成钱包并注入测试资金"""
    global crypto
    data = request.get_json()
    username = data.get("username")
    seed = data.get("seed")
    count = int(data.get("count", 1))

    wallets = generate_btc_keypairs_from_seed(seed, count)
    for private_key, public_key, address in wallets:
        crypto.add_custom_wallet(username, private_key, public_key, address)
        bc.faucet(address, 1000)
    return jsonify({"wallets": [w[2] for w in wallets]})


@app.route('/api/send_message', methods=['POST'])
def send_message():
    """加密并发送消息"""
    global crypto
    data = request.get_json()
    message = data.get("message")
    from_user = data.get("username")
    if not from_user or not message:
        return jsonify({"error": "参数不完整"}), 400

    user, ok = crypto.login_user(from_user, "123")
    if not ok:
        return jsonify({"error": "用户不存在或登录失败"}), 401

    if encrypt_and_send(crypto, from_user=user, message=message):
        return jsonify({"message": "消息加密并发送成功"})
    else:
        return jsonify({"error": "消息加密并发送失败"}), 500


@app.route('/api/decrypt_message', methods=['POST'])
def decrypt_message():
    """解密交易中的消息"""
    global crypto
    data = request.get_json()
    to_user = data.get("username")
    user, ok = crypto.login_user(to_user, "123")
    if not ok:
        return jsonify({"error": "用户不存在或登录失败"}), 401

    decoded_msg = decrypt_from_transactions(user)
    if not decoded_msg:
        return jsonify({"message": "没有待解密的消息"})
    return jsonify({"decoded_message": decoded_msg})


# 允许上传的文件类型
ALLOWED_EXTENSIONS = {'txt'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/send_file_message', methods=['POST'])
def send_file_message():
    """
    上传txt文件，读取内容并加密发送
    Form Data:
      - username: 用户名
      - file: 上传的txt文件
    """
    if 'username' not in request.form or 'file' not in request.files:
        return jsonify({"error": "缺少用户名或文件"}), 400

    username = request.form['username']
    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "未选择文件"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "只允许上传txt文件"}), 400

    # 安全文件名
    filename = secure_filename(file.filename)
    # 读取文件内容
    try:
        content = file.read().decode('utf-8')
    except Exception as e:
        return jsonify({"error": f"读取文件失败: {str(e)}"}), 400

    # 校验最大可发送字节数
    max_bytes = MAX_ADDR_LENGTH * MATCH_BITS

    if len(content.encode('utf-8')) > max_bytes:
        return jsonify({
            "error": f"文件内容过大，无法发送，最大允许 {max_bytes} bytes, 本文件 {len(content.encode('utf-8'))} bytes"
        }), 400
    # 调用加密发送接口
    user, ok = crypto.login_user(username, "123")  # 如果你需要校验密码，可以改成传参
    if not ok:
        return jsonify({"error": "用户不存在或登录失败"}), 401

    if encrypt_and_send(crypto, from_user=user, message=content):
        return jsonify({"message": "文件内容加密并发送成功"})
    else:
        return jsonify({"error": "文件内容加密发送失败"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
