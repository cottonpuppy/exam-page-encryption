import sqlite3
import bcrypt

DB_PATH = '../users.db'  # 数据库文件的路径


# 连接数据库
def connect_db():
    return sqlite3.connect(DB_PATH)


# 添加新用户
def add_user(username, password, role):
    try:
        conn = connect_db()
        cursor = conn.cursor()

        # 对密码进行加盐哈希处理
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor.execute('''
        INSERT INTO users (username, password, role)
        VALUES (?, ?, ?)
        ''', (username, hashed_password, role))

        conn.commit()
        print(f"用户 '{username}' 添加成功！")
    except sqlite3.IntegrityError:
        print(f"用户名 '{username}' 已存在，请选择其他用户名。")
    finally:
        conn.close()


# 删除用户
def delete_user(username):
    try:
        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute('''
        DELETE FROM users WHERE username=?
        ''', (username,))

        if cursor.rowcount > 0:
            print(f"用户 '{username}' 已删除。")
        else:
            print(f"用户 '{username}' 不存在。")

        conn.commit()
    finally:
        conn.close()


# 列出所有用户
def list_users():
    try:
        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute('SELECT*  FROM users')
        users = cursor.fetchall()

        if users:
            print("当前用户列表：")
            for user in users:
                print(f"用户名: {user[0]}, 角色: {user[1]}")
        else:
            print("用户列表为空。")
    finally:
        conn.close()


# 修改用户信息（更新密码或角色）
def update_user(username, new_password=None, new_role=None):
    try:
        conn = connect_db()
        cursor = conn.cursor()

        # 更新密码
        if new_password:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('''
            UPDATE users SET password=? WHERE username=?
            ''', (hashed_password, username))

        # 更新角色
        if new_role:
            cursor.execute('''
            UPDATE users SET role=? WHERE username=?
            ''', (new_role, username))

        if cursor.rowcount > 0:
            print(f"用户 '{username}' 信息更新成功。")
        else:
            print(f"用户 '{username}' 不存在，无法更新。")

        conn.commit()
    finally:
        conn.close()


# 主函数
if __name__ == "__main__":
    while True:
        print("\n用户管理菜单：")
        print("1. 添加新用户")
        print("2. 删除用户")
        print("3. 列出所有用户")
        print("4. 更新用户信息")
        print("5. 退出")

        choice = input("请输入操作编号：")

        if choice == "1":
            username = input("请输入用户名：")
            password = input("请输入密码：")
            role = input("请输入角色（教师/主任/打印员）：")
            add_user(username, password, role)
        elif choice == "2":
            username = input("请输入要删除的用户名：")
            delete_user(username)
        elif choice == "3":
            list_users()
        elif choice == "4":
            username = input("请输入要更新的用户名：")
            new_password = input("请输入新密码（按回车跳过）：")
            new_role = input("请输入新角色（教师/主任/打印员，按回车跳过）：")

            # 处理空输入，确保不会更新为空
            if new_password == "":
                new_password = None
            if new_role == "":
                new_role = None

            update_user(username, new_password, new_role)
        elif choice == "5":
            print("退出程序。")
            break
        else:
            print("无效的选择，请重新输入。")
