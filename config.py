import configparser
import os

# 配置文件路径
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.ini")

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

# 遍历 DEFAULT section，把每个配置项动态设置为模块级变量
for key, value in config['DEFAULT'].items():
    # 尝试类型转换：int / float / bool / str
    if value.lower() in ('true', 'false'):
        value = config['DEFAULT'].getboolean(key)
    else:
        try:
            value = config['DEFAULT'].getint(key)
        except ValueError:
            try:
                value = config['DEFAULT'].getfloat(key)
            except ValueError:
                pass  # 保持字符串
    globals()[key] = value
