- Web框架 ：Tornado
- 数据库 ：SQLite
- 加密技术 ：bcrypt（密码加密）、其他加密算法进行文件加密
- 密钥管理 ：使用Vault系统

## 项目概述
这个项目似乎是一个基于Tornado框架的Web应用，主要功能包括：

1. 用户管理系统 ：支持不同学院的用户，包括管理员、普通用户等角色
2. 文件管理系统 ：允许上传、下载文件，并有审核流程
3. 密钥加密系统 ：使用密钥对文件进行加密保护
## 数据库结构
项目使用SQLite数据库，包含三个主要数据库文件：

1. users.db ：存储用户信息
   
   - 用户名、密码(bcrypt加密)、角色、学院
   - 权限控制：上传、下载、审核权限
2. files.db ：存储文件信息
   
   - 文件名、上传者、所属学院、上传时间
   - 文件状态跟踪（未审核、主任已审核、院长已审核）
3. keys.db ：存储密钥信息
   
   - 用户名与Vault中密钥名称的映射关系

## 1. 信息源安全性

### 用户认证与授权

- 认证机制 ：系统使用用户名/密码认证，密码通过 bcrypt 进行哈希存储，这是一种安全的密码存储方式
- 授权流程 ：
  - 用户注册后需要管理员授权才能使用系统
  - 系统实现了细粒度的权限控制（上传、下载、审核权限）
  - 院长可以管理用户权限，提供了权限分离机制
    
### 数据源保护

- 系统使用 SQLite 数据库存储用户信息、文件元数据和密钥映射
- 数据库访问通过应用程序接口进行，没有直接暴露给用户

## 2. 传输安全性

### HTTPS 实现

```python
# 创建 SSL 上下文，加载证书和密钥
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")

# 启动 HTTPS 服务器，绑定到 IPv4 地址
app.listen(port, ssl_options=ssl_ctx, address="0.0.0.0")
```

- 系统使用 HTTPS 协议（TLS）保护传输层安全
- 默认监听 443 端口（标准 HTTPS 端口）
  
### CORS 配置

```python
def set_default_headers(self):
    # 设置 CORS
    self.set_header("Access-Control-Allow-Origin", "*")
    self.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    self.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
 ```

- 系统配置了 CORS 策略，但使用了通配符 "*"，这可能存在安全风险
- 建议限制为特定的源域名以增强安全性
  
## 3. 信息流转安全性

### 会话管理

```python
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
 ```

- 使用 Redis 存储会话信息，会话有 30 分钟超时机制
- 会话 ID 通过 cookie 传递，使用随机生成的 cookie_secret 增强安全性
  
### 文件审核流程

- 实现了多级审核流程：未审核 → 主任已审核 → 院长已审核
- 每个角色只能查看和操作其权限范围内的文件
- 文件状态变更有明确的权限控制
  
## 4. 密钥管理

### Vault 集成

```python
# Vault 配置
VAULT_ADDR = "http://192.168.175.128:8200"
VAULT_TOKEN = "hvs.L7NCHVkojQuLIJ4U4jJZ0ng0"
client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN,verify= False)
 ```

- 系统使用 HashiCorp Vault 进行密钥管理，这是一个专业的密钥管理解决方案
- 安全风险 ：Vault 地址使用 HTTP 而非 HTTPS，且禁用了证书验证（verify=False）
- 安全风险 ：Vault Token 硬编码在代码中，应考虑使用环境变量或配置文件
### 多层加密机制
```python
# 使用教师的密钥进行第一层加密
teacher_key_name = username
teacher_encrypted_content = self.encrypt_file(file_content, teacher_key_name)

# 使用主任和打印员的密钥进行第二层加密
director_key_name = "director"
printer_key_name = "printer"

director_encrypted_content = self.encrypt_file(teacher_encrypted_content.encode('utf-8'), director_key_name)
printer_encrypted_content = self.encrypt_file(teacher_encrypted_content.encode('utf-8'), printer_key_name)
 ```
- 系统实现了多层加密机制：
  1. 第一层：使用上传者（教师）的密钥加密文件内容
  2. 第二层：使用主任或打印员的密钥进行再次加密
- 解密过程需要两个密钥，增强了安全性
### 密钥生成与存储
```python
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
 ```

- 用户注册时自动在 Vault 中生成密钥
- 密钥名称与用户名关联，存储在专用的密钥数据库中
- 使用 Vault 的 transit 引擎管理密钥，密钥本身不离开 Vault
## 5. 安全风险与建议
### 主要风险
1. Vault 配置不安全 ：
   
   - 使用 HTTP 而非 HTTPS
   - 禁用了证书验证
   - Token 硬编码在代码中
2. CORS 配置过于宽松 ：
   
   - 允许任何源访问 API
3. Redis 连接安全性 ：
   
   - Redis 连接未使用密码认证
   - 使用明文连接（未加密）
4. 密钥管理风险 ：
   
   - 主任和打印员使用固定密钥名称（"director"和"printer"）
   - 未实现密钥轮换机制
