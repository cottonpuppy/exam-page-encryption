import sqlite3
import bcrypt
import os

UDATABASE_PATH = 'users.db'
FDATABASE_PATH = 'files.db'
KDATABASE_PATH = 'keys.db'  # 密钥数据库路径
# 列出所有学院，确保每个学院有自己的管理员账户
COLLEGES = ['计算机学院', '管理学院', '文学院', '理学院', '工学院']

def initialize_users_database():
    """初始化用户数据库，并为每个学院创建默认管理员账户（如果不存在）"""
    try:
        with sqlite3.connect(UDATABASE_PATH) as conn:
            cursor = conn.cursor()

            # 创建用户表，包含权限字段
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                college TEXT NOT NULL,
                is_authorized INTEGER DEFAULT 0,  -- 0表示未授权，1表示已授权
                can_upload INTEGER DEFAULT 0,     -- 0表示无上传权限，1表示有上传权限
                can_download INTEGER DEFAULT 0,   -- 0表示无下载权限，1表示有下载权限
                can_review INTEGER DEFAULT 0,     -- 0表示无审核权限，1表示有审核权限
                UNIQUE(username, role, college)
            )''')

            # 设置硬编码的默认管理员用户名和密码
            default_username = "admin"  # 管理员用户名（可以为每个学院设置相同用户名）
            default_password = "admin"  # 管理员密码（用于测试或开发环境，生产环境应更复杂）

            # 循环创建每个学院的管理员账户（如果不存在）
            for college in COLLEGES:
                # 检查该学院的管理员是否已存在
                cursor.execute("SELECT id FROM users WHERE username=? AND role='管理员' AND college=?", (default_username, college))
                admin_exists = cursor.fetchone()

                if not admin_exists:
                    # 使用 bcrypt 对管理员密码进行加密
                    hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())

                    # 插入管理员账户到指定学院，设置为已授权状态，具有全部权限
                    cursor.execute('''INSERT INTO users (username, password, role, college, is_authorized, can_upload, can_download, can_review)
                                      VALUES (?, ?, ?, ?, ?, 1, 1, 1)''',
                                   (default_username, hashed_password, '管理员', college, 1))

                    print(f"默认管理员账户已为 {college} 创建：用户名为 {default_username}")
                else:
                    print(f"{college} 的管理员账户已存在，无需重新创建")

            # 提交更改
            conn.commit()

    except Exception as e:
        print(f"初始化用户数据库时出错：{e}")

    print("用户数据库已创建并初始化")

def initialize_files_database():
    """初始化文件数据库"""
    try:
        with sqlite3.connect(FDATABASE_PATH) as conn:
            cursor = conn.cursor()

            # 创建文件表，包含文件状态、上传者角色和学院等字段
            cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT NOT NULL,     -- 上传者用户名
                college TEXT NOT NULL,      -- 文件所属学院
                role TEXT NOT NULL,         -- 上传者角色（如管理员、主任等）
                timestamp TEXT NOT NULL,    -- 上传时间
                status TEXT DEFAULT '未审核' -- 文件状态（未审核、主任已审核、院长已审核）
            )''')

            # 提交更改
            conn.commit()

    except Exception as e:
        print(f"初始化文件数据库时出错：{e}")

    print("文件数据库已创建")



def initialize_keys_database():
    """初始化密钥数据库，存储用户名和 Vault 密钥名称"""
    try:
        with sqlite3.connect(KDATABASE_PATH) as conn:
            cursor = conn.cursor()

            # 创建 user_keys 表，用于存储用户名和 Vault 中的密钥名称
            cursor.execute('''CREATE TABLE IF NOT EXISTS user_keys (
                username TEXT PRIMARY KEY,
                key_name TEXT NOT NULL  -- Vault 中的密钥名称
            )''')

            # 提交更改
            conn.commit()

    except Exception as e:
        print(f"初始化密钥数据库时出错：{e}")

    print("密钥数据库已创建并初始化")