from typing import Optional, Awaitable
import tornado.ioloop
import tornado.web
import json
import os
import ssl
import sqlite3
import bcrypt
import time
import aioredis
from tornado.options import define, options
# from docx import Document
from database import initialize_files_database, initialize_users_database, initialize_keys_database
import hvac
import base64

# 定义服务器端口和数据库文件
define("port", default=443, help="run on the given port", type=int)
define("db_file", default="users.db", help="User database file", type=str)
define("file_db", default="files.db", help="Files database file", type=str)
define("keys_db", default="keys.db", help="Keys database file", type=str)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

SESSION_TIMEOUT = 1800  # 会话超时时间为30分钟

# 创建异步 Redis 连接
async def get_redis_connection():
    return await aioredis.from_url("redis://192.168.175.128:6379", decode_responses=True)
# Vault 配置
VAULT_ADDR = "http://192.168.175.128:8200"
#VAULT_TOKEN = "Initial Root Token"
client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN,verify= False)


def generate_user_key(username):
    """在 Vault 中为用户生成密钥并存储密钥名称到数据库"""
    try:
        key_name = username  # 使用用户名作为密钥名称

        # 在 Vault 中创建密钥（使用 transit 秘钥管理）
        client.secrets.transit.create_key(name=key_name)  # 移除 'type' 参数

        # 将用户名和 Vault 中的密钥名称存储到数据库
        with sqlite3.connect(options.keys_db) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO user_keys (username, key_name) VALUES (?, ?)", (username, key_name))
            conn.commit()

        print(f"已在 Vault 中为用户 {username} 生成密钥并存储密钥名称")

    except sqlite3.IntegrityError:
        print(f"用户 {username} 的密钥名称已存在，未重新生成")
    except Exception as e:
        print(f"生成用户密钥时出错：{e}")



# 基础处理器，处理 CORS 和会话管理
class BaseHandler(tornado.web.RequestHandler):
    async def prepare(self):
        self.redis_client = await get_redis_connection()  # 获取异步 Redis 连接
        session_id = self.get_cookie("session_id")
        if session_id:
            session_data = await self.redis_client.get(session_id)
            if session_data:
                await self.redis_client.expire(session_id, SESSION_TIMEOUT)  # 更新会话过期时间
                self.current_user = json.loads(session_data)
            else:
                self.current_user = None
        else:
            self.current_user = None

    def set_default_headers(self):
        # 设置 CORS
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")

    def options(self):
        self.set_status(204)
        self.finish()

    async def validate_user(self):
        """确保用户已登录"""
        if not self.current_user:
            self.set_status(401)
            self.write({"status": "error", "message": "请先登录"})
            await self.finish()
            return False
        return True

    async def validate_role(self, required_role):
        """验证用户角色"""
        if not self.current_user or self.current_user.get("role") != required_role:
            self.set_status(403)
            self.write({"status": "error", "message": "无权限访问此资源"})
            await self.finish()
            return False
        return True

    async def check_permission(self, username, permission_type):
        """通用权限检查方法"""
        try:
            with sqlite3.connect(options.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT {permission_type} FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                return result and result[0] == 1
        except sqlite3.Error as e:
            print(f"权限检查失败: {e}")

# 登录处理器
class LoginHandler(BaseHandler):
    async def post(self):
        try:
            data = json.loads(self.request.body)
            username = data.get('username')
            password = data.get('password')
            role = data.get('role')
            college = data.get('college')

            if not all([username, password, role, college]):
                self.write({"status": "error", "message": "所有字段都是必需的。"})
                return

            with sqlite3.connect(options.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT password, is_authorized FROM users WHERE username=? AND role=? AND college=?',
                               (username, role, college))
                user = cursor.fetchone()

            if user:
                stored_password, is_authorized = user
                if not is_authorized:
                    self.write({"status": "error", "message": "用户尚未获得登录授权，请联系管理员。"})
                    return

                if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                    session_id = os.urandom(24).hex()
                    session_data = {
                        "username": username,
                        "role": role,
                        "college": college,
                        "timestamp": time.time()
                    }
                    await self.redis_client.setex(session_id, SESSION_TIMEOUT, json.dumps(session_data))
                    self.set_cookie("session_id", session_id)
                    self.write({"status": "success", "message": f"欢迎，{role}！"})
                else:
                    self.write({"status": "error", "message": "无效的用户名或密码。"})
            else:
                self.write({"status": "error", "message": "无效的登录信息。"})
        except sqlite3.Error as db_error:
            print(f"数据库错误: {db_error}")
            self.set_status(500)
            self.write({"status": "error", "message": "数据库操作失败"})
        except Exception as e:
            print(f"登录错误: {e}")
            self.set_status(500)
            self.write({"status": "error", "message": "内部错误"})
class RegisterHandler(BaseHandler):
    def post(self):
        try:
            # 从请求体中获取数据
            data = json.loads(self.request.body)
            username = data.get('username')
            password = data.get('password')
            role = data.get('role')
            college = data.get('college')

            # 检查输入的有效性
            if not all([username, password, role, college]):
                self.write({"status": "error", "message": "所有字段都是必需的。"})
                return

            # 连接数据库
            with sqlite3.connect(options.db_file) as conn:
                cursor = conn.cursor()

                # 检查用户名是否已存在
                cursor.execute('SELECT id FROM users WHERE username=? AND role=? AND college=?',
                               (username, role, college))
                existing_user = cursor.fetchone()

                if existing_user:
                    self.write({"status": "error", "message": "用户名已存在，请选择其他用户名。"})
                    return

                # 对密码进行加盐哈希
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                # 将用户数据存入数据库，设置权限为默认值0
                cursor.execute('''INSERT INTO users (username, password, role, college, is_authorized, can_upload, can_download, can_review)
                                                  VALUES (?, ?, ?, ?, ?, 0, 0, 0)''',
                               (username, hashed_password, role, college, 0))

            # 在 Vault 中为用户生成密钥并存储密钥名称到密钥数据库
            generate_user_key(username)

            self.write({"status": "success", "message": "注册成功！请等待管理员授权。"})
        except sqlite3.IntegrityError:
            self.write({"status": "error", "message": "用户名已存在，请选择其他用户名。"})
        except json.JSONDecodeError:
            self.write({"status": "error", "message": "请求数据格式错误，请检查输入数据格式是否为有效的JSON。"})
        except Exception as e:
            self.write({"status": "error", "message": f"内部错误: {str(e)}"})


# 定义一个处理主页请求的处理器，渲染 login.html 文件
class MainHandler(BaseHandler):
    def get(self):
        self.render("login.html")  # 渲染 login.html 文件

# 定义一个管理员主页请求的处理器
class AdministratorHandler(BaseHandler):
    async def get(self):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info = await self.redis_client.get(session_id)
            if user_info:
                user_info = json.loads(user_info)
                if user_info.get("role") == "管理员":  # 确保用户角色是“管理员”
                    self.render("administrator.html")  # 渲染 administrator.html 页面
                    return

        self.redirect("/")  # 如果没有登录或没有权限，重定向到登录页面


# 定义一个处理教师页面请求的处理器
class TeacherHandler(BaseHandler):
    async def get(self):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info = await self.redis_client.get(session_id)
            if user_info:
                user_info = json.loads(user_info)
                if user_info.get("role") == "教师":  # 确保用户角色是“教师”
                    self.render("teacher.html")  # 渲染 teacher.html 页面
                    return

        self.redirect("/")  # 如果没有登录或没有权限，重定向到登录页面


class DirectorHandler(BaseHandler):
    async def get(self):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info = await self.redis_client.get(session_id)
            if user_info:
                user_info = json.loads(user_info)
                if user_info.get("role") == "主任":  # 确保用户角色是“主任”
                    self.render("director.html")  # 渲染 director.html 页面
                    return

        self.redirect("/")  # 如果没有登录或没有权限，重定向到登录页面


# 院长页面处理器
class DeanHandler(BaseHandler):
    async def get(self):
        if await self.validate_user():  # Validate user session
            if self.current_user.get("role") == "院长":
                self.render("dean.html")  # Render the dean's page
            else:
                self.redirect("/")  # Redirect to login if not a dean
        else:
            self.redirect("/")  # Redirect if user is not logged in

class PrinterHandler(BaseHandler):
    async def get(self):
        # 检查用户是否有权限访问打印员页面
        if await self.validate_user():
            if self.current_user.get("role") == "打印员":
                self.render("printer.html")  # 渲染打印员页面
            else:
                self.redirect("/")  # 重定向到主页
        else:
            self.redirect("/")  # 如果用户未登录，重定向到主页

class PrinterFileHandler(BaseHandler):
    async def get(self):
        # 验证用户是否为打印员
        if await self.validate_user():
            if self.current_user.get("role") == "打印员":
                try:
                    with sqlite3.connect(options.file_db) as conn:
                        cursor = conn.cursor()
                        # 查询状态为“院长已审核”的文件
                        cursor.execute("""
                            SELECT name, username, timestamp, status 
                            FROM files 
                            WHERE status = '院长已审核'
                        """)
                        files = [{"name": row[0], "username": row[1], "timestamp": row[2], "status": row[3]} for row in cursor.fetchall()]

                    # 返回 JSON 数据
                    self.write({"status": "success", "files": files})
                except sqlite3.Error as e:
                    print(f"Error fetching files: {e}")
                    self.set_status(500)
                    self.write({"status": "error", "message": "内部服务器错误"})
            else:
                self.set_status(403)
                self.write({"status": "error", "message": "无权限访问此资源"})
        else:
            self.set_status(401)
            self.write({"status": "error", "message": "未授权的请求"})


#管理员用户显示
class AdminUsersHandler(BaseHandler):
    async def get(self):
        session_id = self.get_cookie("session_id")

        # 根据 session_id 从 Redis 获取用户信息
        if session_id:
            user_info_json = await self.redis_client.get(session_id)
            if user_info_json:
                user_info = json.loads(user_info_json)

                # 确保 user_info 包含 role 和 college 信息且用户是管理员
                if user_info.get("role") == "管理员":
                    admin_college = user_info.get("college")  # 获取管理员所属学院
                    try:
                        with sqlite3.connect(options.db_file) as conn:
                            cursor = conn.cursor()
                            # 查询同一个学院的用户信息
                            cursor.execute("SELECT username, role, college, is_authorized FROM users WHERE college = ?", (admin_college,))
                            users = [{"username": row[0], "role": row[1], "college": row[2], "is_authorized": row[3]} for row in cursor.fetchall()]
                            self.write(json.dumps(users))  # 返回学院内的用户数据
                    except Exception as e:
                        print("Error fetching users:", e)
                        self.set_status(500)
                        self.write({"status": "error", "message": "内部服务器错误"})
                    return

        self.set_status(403)
        self.write({"status": "error", "message": "无权访问用户数据"})


#管理员用户删除
class AdminDeleteUsersHandler(BaseHandler):
    async def delete(self, username):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info_json = await self.redis_client.get(session_id)
            if user_info_json:
                user_info = json.loads(user_info_json)

                # 确保用户具有管理员角色
                if user_info.get("role") == "管理员":
                    try:
                        with sqlite3.connect(options.db_file) as conn:
                            cursor = conn.cursor()
                            # 使用带参数的 SQL 防止 SQL 注入
                            cursor.execute("DELETE FROM users WHERE username = ? AND college = ?",
                                           (username, user_info.get("college")))

                            # 检查删除操作是否成功
                            if cursor.rowcount == 0:
                                self.set_status(404)
                                self.write({"status": "error", "message": "用户不存在或不属于您的学院"})
                            else:
                                conn.commit()  # 提交删除操作
                                self.write({"status": "success", "message": f"用户 {username} 已成功删除"})
                        return
                    except Exception as e:
                        print("Error deleting user:", e)
                        self.set_status(500)
                        self.write({"status": "error", "message": "内部服务器错误"})
                        return

        # 权限不足或未登录
        self.set_status(403)
        self.write({"status": "error", "message": "无权删除用户"})

#管理员用户授权
class AuthorizeUserHandler(BaseHandler):
    async def put(self, username):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info_json = await self.redis_client.get(session_id)
            if user_info_json:
                user_info = json.loads(user_info_json)
                print(f"Received PUT request to authorize user: {username}")  # 添加调试信息

                # 确保用户是管理员
                if user_info.get("role") == "管理员":
                    try:
                        with sqlite3.connect(options.db_file) as conn:
                            cursor = conn.cursor()

                            # 检查用户是否存在
                            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                            user = cursor.fetchone()

                            if user is None:
                                self.set_status(404)
                                self.write({"status": "error", "message": "未找到该用户。"})
                                return

                            # 更新用户的授权状态
                            cursor.execute("UPDATE users SET is_authorized = ? WHERE username = ?", (1, username))
                            conn.commit()

                            if cursor.rowcount > 0:
                                self.write({"status": "success", "message": f"用户 {username} 已成功授权。"})
                            else:
                                self.set_status(404)
                                self.write({"status": "error", "message": "未更新任何行，可能该用户已被授权。"})
                    except Exception as e:
                        self.set_status(500)
                        self.write({"status": "error", "message": f"内部错误: {str(e)}"})
                    return

        self.set_status(403)
        self.write({"status": "error", "message": "无权执行此操作"})


#管理员用户取消授权
class RevokeAuthorizationHandler(BaseHandler):
    async def put(self, username):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info_json = await self.redis_client.get(session_id)
            if user_info_json:
                user_info = json.loads(user_info_json)
                print(f"Received PUT request to revoke authorization for user: {username}")  # 添加调试信息

                # 确保用户是管理员
                if user_info.get("role") == "管理员":
                    try:
                        with sqlite3.connect(options.db_file) as conn:
                            cursor = conn.cursor()

                            # 检查用户是否存在
                            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                            user = cursor.fetchone()

                            if user is None:
                                self.set_status(404)
                                self.write({"status": "error", "message": "未找到该用户。"})
                                return

                            # 更新用户的授权状态为未授权
                            cursor.execute("UPDATE users SET is_authorized = ? WHERE username = ?", (0, username))
                            conn.commit()

                            if cursor.rowcount > 0:
                                self.write({"status": "success", "message": f"用户 {username} 的授权已成功取消。"})
                            else:
                                self.set_status(404)
                                self.write({"status": "error", "message": "未更新任何行，可能该用户已未授权。"})
                    except Exception as e:
                        self.set_status(500)
                        self.write({"status": "error", "message": f"内部错误: {str(e)}"})
                    return

        self.set_status(403)
        self.write({"status": "error", "message": "无权执行此操作"})


# 获取院长所在学院的所有用户处理器
class DeanUsersHandler(BaseHandler):
    async def get(self):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info_json = await self.redis_client.get(session_id)
            if user_info_json:
                user_info = json.loads(user_info_json)

                # 确保请求者为院长
                if user_info.get("role") == "院长":
                    dean_college = user_info.get("college")  # 获取院长所在学院
                    try:
                        with sqlite3.connect(options.db_file) as conn:
                            cursor = conn.cursor()
                            # 查询院长所在学院的用户信息
                            cursor.execute("SELECT username, role, college, is_authorized, can_upload, can_download, can_review FROM users WHERE college = ?", (dean_college,))
                            users = [{
                                "username": row[0],
                                "role": row[1],
                                "college": row[2],
                                "is_authorized": row[3],
                                "can_upload": row[4],
                                "can_download": row[5],
                                "can_review": row[6]
                            } for row in cursor.fetchall()]
                            self.write({"status": "success", "users": users})
                    except sqlite3.Error as e:
                        print("Error fetching users:", e)
                        self.set_status(500)
                        self.write({"status": "error", "message": "内部服务器错误"})
                    return

        self.set_status(403)
        self.write({"status": "error", "message": "无权访问用户数据"})

# 获取主任审核过的文件处理器


class DeanReviewedFilesHandler(BaseHandler):
    async def get(self):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info_json = await self.redis_client.get(session_id)
            if user_info_json:
                user_info = json.loads(user_info_json)

                # 确保请求者为院长
                if user_info.get("role") == "院长":
                    try:
                        with sqlite3.connect(options.file_db) as conn:
                            cursor = conn.cursor()
                            # 查询状态为“主任已审核”或“院长已审核”的文件
                            cursor.execute("""
                                SELECT id, name, username, timestamp, status 
                                FROM files 
                                WHERE status IN ('主任已审核', '院长已审核')
                            """)
                            files = [{
                                "id": row[0],
                                "name": row[1],
                                "username": row[2],
                                "timestamp": row[3],
                                "status": row[4]
                            } for row in cursor.fetchall()]

                            # 返回成功状态和文件列表
                            self.write({"status": "success", "files": files})
                        return
                    except sqlite3.Error as e:
                        print("Error fetching files:", e)
                        self.set_status(500)
                        self.write({"status": "error", "message": "内部服务器错误"})
                        return

        # 权限不足或未登录
        self.set_status(403)
        self.write({"status": "error", "message": "无权访问文件数据"})


class DeanFileApprovalHandler(BaseHandler):
    async def put(self, file_id):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info_json = await self.redis_client.get(session_id)
            if user_info_json:
                user_info = json.loads(user_info_json)

                # 确保请求者角色为院长
                if user_info.get("role") == "院长":
                    try:
                        # 解析请求体获取新的状态
                        data = json.loads(self.request.body)
                        new_status = data.get("status")

                        # 调试信息
                        print(f"Received status update for file {file_id}: {new_status}")

                        # 验证新的状态是否有效
                        if new_status not in ["主任已审核", "院长已审核"]:
                            self.set_status(400)
                            self.write({"status": "error", "message": "无效的状态值"})
                            return

                        with sqlite3.connect(options.file_db) as conn:
                            cursor = conn.cursor()

                            # 检查文件是否存在
                            cursor.execute("SELECT status FROM files WHERE id = ?", (file_id,))
                            file = cursor.fetchone()

                            if file is None:
                                self.set_status(404)
                                self.write({"status": "error", "message": "文件不存在"})
                                return

                            # 更新文件状态为新的目标状态
                            cursor.execute("UPDATE files SET status = ? WHERE id = ?", (new_status, file_id))
                            conn.commit()
                            self.write({"status": "success", "message": f"文件状态已更新为: {new_status}"})
                        return
                    except json.JSONDecodeError:
                        self.set_status(400)
                        self.write({"status": "error", "message": "请求数据格式无效"})
                        return
                    except sqlite3.Error as e:
                        self.set_status(500)
                        self.write({"status": "error", "message": f"数据库操作失败: {str(e)}"})
                        return

        # 权限不足或未登录
        self.set_status(403)
        self.write({"status": "error", "message": "无权执行此操作"})

# 用户权限管理处理器，供院长使用
class DeanUserPermissionHandler(BaseHandler):
    async def put(self, username):
        session_id = self.get_cookie("session_id")
        if session_id:
            user_info_json = await self.redis_client.get(session_id)
            if user_info_json:
                user_info = json.loads(user_info_json)

                # 确保请求者是院长
                if user_info.get("role") == "院长":
                    try:
                        data = json.loads(self.request.body)
                        can_upload = data.get("can_upload")
                        can_download = data.get("can_download")
                        can_review = data.get("can_review")

                        # 至少一个权限字段存在
                        if can_upload is None and can_download is None and can_review is None:
                            self.write({"status": "error", "message": "至少需要提供一个权限字段"})
                            return

                        with sqlite3.connect(options.db_file) as conn:
                            cursor = conn.cursor()

                            # 检查用户是否存在
                            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                            if cursor.fetchone() is None:
                                self.set_status(404)
                                self.write({"status": "error", "message": "用户不存在"})
                                return

                            # 更新权限
                            if can_upload is not None:
                                cursor.execute("UPDATE users SET can_upload = ? WHERE username = ?", (int(can_upload), username))
                            if can_download is not None:
                                cursor.execute("UPDATE users SET can_download = ? WHERE username = ?", (int(can_download), username))
                            if can_review is not None:
                                cursor.execute("UPDATE users SET can_review = ? WHERE username = ?", (int(can_review), username))

                            conn.commit()
                            self.write({"status": "success", "message": f"用户 {username} 的权限已更新"})
                        return
                    except sqlite3.Error as e:
                        self.set_status(500)
                        self.write({"status": "error", "message": f"数据库操作失败: {str(e)}"})
                        return
                    except json.JSONDecodeError:
                        self.set_status(400)
                        self.write({"status": "error", "message": "请求数据格式错误"})
                        return

        # 权限不足或未登录
        self.set_status(403)
        self.write({"status": "error", "message": "无权执行此操作"})


# 定义文件上传处理器
import base64


class UploadHandler(BaseHandler):
    async def post(self):
        # 验证登录状态
        session_id = self.get_cookie("session_id")
        if not session_id:
            self.write({"status": "error", "message": "请先登录"})
            return

        # 获取用户信息
        user_info_json = await self.redis_client.get(session_id)
        if not user_info_json:
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info = json.loads(user_info_json)
        username = user_info["username"]

        # 检查用户是否有上传权限
        if not await self.check_permission(username, "can_upload"):
            self.write({"status": "error", "message": "无上传权限"})
            return

        try:
            # 获取上传的文件
            file_info = self.request.files['file'][0]
            filename = os.path.basename(file_info['filename'])
            file_content = file_info['body']  # 获取文件内容
            timestamp = self.get_body_argument('timestamp', None)

            if not timestamp:
                self.write({"status": "error", "message": "缺少时间戳信息"})
                return

            # 使用教师的密钥进行第一层加密
            teacher_key_name = username
            teacher_encrypted_content = self.encrypt_file(file_content, teacher_key_name)

            # 使用主任和打印员的密钥进行第二层加密
            director_key_name = "director"
            printer_key_name = "printer"

            director_encrypted_content = self.encrypt_file(teacher_encrypted_content.encode('utf-8'), director_key_name)
            printer_encrypted_content = self.encrypt_file(teacher_encrypted_content.encode('utf-8'), printer_key_name)

            # 存储加密后的文件，不存储原始文件
            self.store_encrypted_file(director_encrypted_content, f"{filename}_director.enc")
            self.store_encrypted_file(printer_encrypted_content, f"{filename}_printer.enc")

            # 保存文件信息到数据库
            self.create_file_entry(filename, username, timestamp)

            self.write({"status": "success", "message": "文件上传并加密成功"})
        except Exception as e:
            self.write({"status": "error", "message": f"文件上传失败: {str(e)}"})

    def encrypt_file(self, content, key_name):
        """使用 Vault Transit 加密文件内容"""
        encoded_content = base64.b64encode(content).decode('utf-8')
        response = client.secrets.transit.encrypt_data(
            name=key_name,
            plaintext=encoded_content
        )
        ciphertext = response['data']['ciphertext']

        # 调试信息
        print(f"生成的密文（带前缀）: {ciphertext[:100]}...")
        return ciphertext

    def store_encrypted_file(self, encrypted_content, filename):
        """将加密内容保存为文件"""
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(file_path, 'w') as f:
            f.write(encrypted_content)
        print(f"已存储加密文件：{filename}")

    def create_file_entry(self, filename, username, timestamp):
        """将文件信息保存到数据库中"""
        try:
            with sqlite3.connect(options.file_db) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO files (name, username, timestamp, status)
                    VALUES (?, ?, ?, ?)
                ''', (filename, username, timestamp, "未审核"))
                conn.commit()
        except Exception as e:
            raise Exception(f"数据库操作失败: {str(e)}")


# 定义文件删除处理器

class DeleteHandler(BaseHandler):
    async def post(self):
        session_id = self.get_cookie("session_id")
        if not session_id:
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info_json = await self.redis_client.get(session_id)
        if not user_info_json:
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info = json.loads(user_info_json)

        try:
            data = json.loads(self.request.body)
            filename = os.path.basename(data.get('filename'))  # 确保文件名安全

            # 构造加密文件的路径
            director_file_path = os.path.join(UPLOAD_FOLDER, f"{filename}_director.enc")
            printer_file_path = os.path.join(UPLOAD_FOLDER, f"{filename}_printer.enc")

            # 删除加密版本文件
            files_deleted = []
            for file_path in [director_file_path, printer_file_path]:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    files_deleted.append(file_path)
                else:
                    print(f"文件不存在: {file_path}")

            if files_deleted:
                # 从数据库中删除文件信息
                with sqlite3.connect(options.file_db) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM files WHERE name=?', (filename,))
                    conn.commit()

                self.write({
                    "status": "success",
                    "message": f"加密文件删除成功: {', '.join(files_deleted)}"
                })
            else:
                self.write({"status": "error", "message": "加密文件不存在"})
        except Exception as e:
            self.write({"status": "error", "message": f"文件删除失败: {str(e)}"})


class FileListHandler(BaseHandler):
    async def get(self):
        session_id = self.get_cookie("session_id")
        if not session_id:
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info_json = await self.redis_client.get(session_id)
        if not user_info_json:
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info = json.loads(user_info_json)
        username = user_info["username"]  # 获取当前用户的用户名

        try:
            with sqlite3.connect(options.file_db) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT name, username, timestamp, status FROM files WHERE username = ?', (username,))
                files = cursor.fetchall()

            files_list = [{"name": file[0], "username": file[1], "timestamp": file[2], "status": file[3]} for file in
                          files]

            self.write({"status": "success", "files": files_list})
        except Exception as e:
            self.write({"status": "error", "message": f"文件列表加载失败: {str(e)}"})


#主任列表文件处理器
class DirectorFileListHandler(BaseHandler):
    async def get(self):
        # 验证当前用户身份和权限，确保用户具有查看权限
        session_id = self.get_cookie("session_id")
        if not session_id:
            self.set_status(401)
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info_json = await self.redis_client.get(session_id)
        if not user_info_json:
            self.set_status(401)
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info = json.loads(user_info_json)

        try:
            # 查询数据库中所有状态为“未审核”的文件
            with sqlite3.connect(options.file_db) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name, username, timestamp, status FROM files")
                files = cursor.fetchall()

            # 将文件数据转换为字典列表格式以返回给前端
            files_list = [{"name": file[0], "username": file[1], "timestamp": file[2], "status": file[3]} for file in files]

            self.write({"status": "success", "files": files_list})
        except Exception as e:
            self.set_status(500)
            self.write({"status": "error", "message": f"文件列表加载失败: {str(e)}"})


class ReviewHandler(BaseHandler):
    async def post(self):
        session_id = self.get_cookie("session_id")
        if not session_id:
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info_json = await self.redis_client.get(session_id)
        if not user_info_json:
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info = json.loads(user_info_json)
        username = user_info["username"]

        # 检查用户是否具有审核权限
        if not await self.check_permission(username, "can_review"):
            self.write({"status": "error", "message": "无审核权限"})
            return

        try:
            data = json.loads(self.request.body)
            filename = data.get('filename')
            current_status = data.get('current_status')

            # 切换文件状态
            new_status = "主任已审核" if current_status == "未审核" else "未审核"

            # 更新文件状态
            with sqlite3.connect(options.file_db) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE files SET status=? WHERE name=?", (new_status, filename))
                conn.commit()

            self.write({"status": "success", "message": f"文件状态已更新为: {new_status}"})
        except Exception as e:
            self.write({"status": "error", "message": f"文件审核失败: {str(e)}"})



class CheckDownloadPermissionHandler(BaseHandler):
    async def post(self):
        session_id = self.get_cookie("session_id")
        if not session_id:
            self.set_status(401)
            self.write({"status": "error", "message": "请先登录"})
            return

        # 获取当前用户信息
        user_info_json = await self.redis_client.get(session_id)
        if not user_info_json:
            self.set_status(401)
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info = json.loads(user_info_json)
        username = user_info["username"]

        # 检查用户的下载权限
        if not await self.check_permission(username, "can_download"):
            self.set_status(403)
            self.write({"status": "error", "message": "您没有足够的权限进行文件下载，请联系管理员获取权限"})
            return

        # 权限通过
        self.write({"status": "success", "message": "权限验证通过，可以下载文件"})






class OpenFileHandler(BaseHandler):
    async def get(self):
        session_id = self.get_cookie("session_id")
        if not session_id:
            self.set_status(401)
            self.write({"status": "error", "message": "请先登录"})
            print("未找到 session_id，用户未登录")
            return

        user_info_json = await self.redis_client.get(session_id)
        if not user_info_json:
            self.set_status(401)
            self.write({"status": "error", "message": "请先登录"})
            print("Redis 中未找到 session 数据，用户未登录")
            return

        user_info = json.loads(user_info_json)
        username = user_info["username"]
        user_role = user_info["role"]

        print(f"用户名: {username}, 角色: {user_role}")

        # 确保用户具有查看权限
        if not await self.check_permission(username, "can_download"):
            self.set_status(403)
            self.write({"status": "error", "message": "您没有权限查看此文件"})
            print(f"用户 {username} 没有下载权限")
            return

        try:
            # 获取文件名和上传者信息
            filename = os.path.basename(self.get_query_argument('filename'))
            print(f"请求预览的文件名: {filename}")

            # 查询文件信息，获取上传者用户名
            with sqlite3.connect(options.file_db) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username FROM files WHERE name = ?", (filename,))
                result = cursor.fetchone()
                if result:
                    uploader_username = result[0]
                    print(f"文件上传者: {uploader_username}")
                else:
                    self.set_status(404)
                    self.write({"status": "error", "message": "文件不存在"})
                    print("数据库中未找到文件记录")
                    return

            # 根据用户角色选择相应的文件版本路径
            if user_role == "主任":
                file_path = os.path.join(UPLOAD_FOLDER, f"{filename}_director.enc")
                outer_key_name = "director"
            elif user_role == "打印员":
                file_path = os.path.join(UPLOAD_FOLDER, f"{filename}_printer.enc")
                outer_key_name = "printer"
            else:
                self.set_status(403)
                self.write({"status": "error", "message": "无效的用户角色"})
                print(f"无效的用户角色: {user_role}")
                return

            print(f"解密文件路径: {file_path}, 外层密钥: {outer_key_name}")

            if not os.path.exists(file_path):
                self.set_status(404)
                self.write({"status": "error", "message": "文件不存在"})
                print("文件路径不存在")
                return

            # 读取加密文件内容
            with open(file_path, 'r') as f:
                encrypted_data = f.read().strip()
            print(f"外层加密数据: {encrypted_data[:100]}...")

            # 检查外层加密数据的前缀并尝试解密
            if not encrypted_data.startswith("vault:v1:"):
                self.set_status(400)
                self.write({"status": "error", "message": "密文格式无效"})
                print("密文缺少 vault:v1: 前缀")
                return

            # 第一步：使用主任或打印员的密钥解密外层加密
            response = client.secrets.transit.decrypt_data(
                name=outer_key_name,
                ciphertext=encrypted_data
            )
            inner_encrypted_data_base64 = response["data"]["plaintext"]
            print(f"内层加密数据（Base64 编码）: {inner_encrypted_data_base64[:100]}...")

            # 将内层加密数据从 Base64 解码为原始带 `vault:` 前缀的密文
            inner_encrypted_data = base64.b64decode(inner_encrypted_data_base64).decode("utf-8")
            print(f"内层加密数据（用于解密）：{inner_encrypted_data[:100]}...")

            # 第二步：使用上传者（教师）的密钥解密内层加密
            teacher_key_name = uploader_username
            response = client.secrets.transit.decrypt_data(
                name=teacher_key_name,
                ciphertext=inner_encrypted_data
            )
            decrypted_data_base64 = response["data"]["plaintext"]
            print(f"解密后的数据（Base64 编码）: {decrypted_data_base64[:100]}...")

            # 将 Base64 编码的解密内容解码为原始二进制数据
            decrypted_data = base64.b64decode(decrypted_data_base64)

            # 设置 Content-Type 头，以便在浏览器中正确显示
            if filename.endswith('.txt'):
                self.set_header('Content-Type', 'text/plain; charset=utf-8')
            elif filename.endswith('.html'):
                self.set_header('Content-Type', 'text/html; charset=utf-8')
            elif filename.endswith('.pdf'):
                self.set_header('Content-Type', 'application/pdf')
            else:
                # 对于其他文件类型，例如图片
                self.set_header('Content-Type', 'application/octet-stream')

            # 直接将解密后的文件内容返回，而不是下载
            self.write(decrypted_data)
            self.finish()
            print("文件成功解密并发送到客户端")

        except Exception as e:
            self.set_status(500)
            self.write({"status": "error", "message": f"文件预览失败: {str(e)}"})
            print(f"文件预览失败: {e}")

# 文件打印处理器
class PrintHandler(BaseHandler):
    async def post(self):
        session_id = self.get_cookie("session_id")
        if not session_id:
            self.write({"status": "error", "message": "请先登录"})
            return

        user_info_json = await self.redis_client.get(session_id)
        if not user_info_json:
            self.write({"status": "error", "message": "请先登录"})
            return

        try:
            data = json.loads(self.request.body)
            filename = data.get('filename')
            file_path = os.path.join(UPLOAD_FOLDER, filename)

            if not os.path.exists(file_path):
                self.set_status(404)
                self.write({"status": "error", "message": "文件不存在"})
                return

            os.system(f'lpr {file_path}')
            self.write({"status": "success", "message": f"文件 {filename} 已发送至打印机"})
        except Exception as e:
            self.set_status(500)
            self.write({"status": "error", "message": f"文件打印失败: {str(e)}"})
            print(f"文件打印失败: {str(e)}")

# 配置 Tornado 应用程序
def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),  # 根路径，用于提供 login.html 页面
        (r"/login", LoginHandler),  # 处理登录请求
        (r"/register", RegisterHandler),  # 处理注册请求
        (r"/administrator", AdministratorHandler),  # 页面管理员
        (r"/teacher", TeacherHandler),  # 教师页面
        (r"/director", DirectorHandler),  # 主任页面
        (r"/dean", DeanHandler),
        (r"/printer", PrinterHandler),  # 打印员页面
        (r"/admin/users", AdminUsersHandler),  # 用户管理
        (r"/admin/users/([^/]+)", AdminDeleteUsersHandler),
        (r"/admin/users/([a-zA-Z0-9]+)/authorize", AuthorizeUserHandler),    # 授权用户的路由
        (r"/admin/users/(.*)/revoke", RevokeAuthorizationHandler),  # 新增取消授权的路由
        (r"/files/([^/]+)/review", DeanFileApprovalHandler),  # 院长审核文件路由
        (r"/users/([a-zA-Z0-9]+)/permissions", DeanUserPermissionHandler),  # 院长管理用户权限路由
        (r"/dean/users", DeanUsersHandler),  # 获取院长所在学院的所有用户
        (r"/dean/reviewed_files", DeanReviewedFilesHandler),  # 获取主任已审核的文件
        (r"/printer/files", PrinterFileHandler),
        (r"/upload", UploadHandler),  # 处理文件上传
        (r"/delete", DeleteHandler),  # 处理文件删除
        (r"/files", FileListHandler),  # 处理教师文件列表请求
        (r"/unreviewed_files", DirectorFileListHandler),
        (r"/review", ReviewHandler),  # 处理文件审核请求
        (r"/check_permission", CheckDownloadPermissionHandler),  # 用于检查下载权限
        (r"/fileContent", OpenFileHandler),
        (r"/print", PrintHandler),  # 添加文件打印接口

        (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": os.path.join(os.path.dirname(__file__), "static")})
    ],

        template_path=os.path.dirname(__file__),  # 模板文件路径配置为当前文件夹
        static_path=os.path.join(os.path.dirname(__file__), "static"),  # 设置静态文件路径
        cookie_secret=os.urandom(24).hex()  # 用于安全设置 cookie
    )


# 启动 Tornado 服务器
if __name__ == "__main__":
    port = 8888  # 监听的端口
    app = make_app()

    initialize_users_database()
    initialize_files_database()
    initialize_keys_database()
    # 创建 SSL 上下文，加载证书和密钥
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # 启动 HTTPS 服务器，绑定到 IPv4 地址
    app.listen(port, ssl_options=ssl_ctx, address="0.0.0.0")



    # 输出服务器启动的信息
    print(f"HTTPS 服务器已启动，请访问：https://localhost:{port}")

    tornado.ioloop.IOLoop.current().start()