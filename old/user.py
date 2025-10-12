import json
import bcrypt
from wallet import Wallet

USERS_FILE = "users.json"

def load_users():
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def register(username, password):
    users = load_users()
    if username in users:
        return False, "用户名已存在"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    wallet = Wallet()
    users[username] = {
        "password": hashed,
        "private_key": wallet.private_key.to_string().hex(),
        "address": wallet.get_address()
    }
    save_users(users)
    return True, "注册成功"

def login(username, password):
    users = load_users()
    if username not in users:
        return False, "用户不存在"
    if bcrypt.checkpw(password.encode(), users[username]["password"].encode()):
        return True, users[username]
    return False, "密码错误"
