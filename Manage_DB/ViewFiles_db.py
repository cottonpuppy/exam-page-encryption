import sqlite3
import os

# 数据库文件路径
DB_FILE = "../files.db"

# 确保数据库文件存在
if not os.path.exists(DB_FILE):
    print(f"Error: 数据库文件 '{DB_FILE}' 不存在！")
    exit(1)

def view_files():
    try:
        # 连接到数据库
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # 查询文件信息
        cursor.execute("SELECT id, name, username, timestamp, status FROM files")
        rows = cursor.fetchall()

        # 打印表格信息
        if rows:
            print("\nfiles 表内容如下：")
            print("-" * 70)
            print(f"{'ID':<5} {'文件名':<20} {'上传者':<15} {'时间戳':<20} {'状态':<10}")
            print("-" * 70)
            for row in rows:
                print(f"{row[0]:<5} {row[1]:<20} {row[2]:<15} {row[3]:<20} {row[4]:<10}")
            print("-" * 70)
        else:
            print("\nfiles 表中没有记录。")

    except sqlite3.Error as e:
        print(f"数据库错误: {str(e)}")
    except Exception as e:
        print(f"错误: {str(e)}")
    finally:
        if conn:
            conn.close()

def delete_file():
    while True:
        try:
            file_id = input("请输入要删除的文件 ID (按 'q' 退出): ")
            if file_id.lower() == 'q':
                print("退出删除操作。")
                break

            # 连接到数据库
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            # 删除指定 ID 的文件记录
            cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()

            if cursor.rowcount > 0:
                print(f"成功删除 ID 为 {file_id} 的文件记录。")
            else:
                print(f"未找到 ID 为 {file_id} 的文件记录。")

        except sqlite3.Error as e:
            print(f"数据库错误: {str(e)}")
        except Exception as e:
            print(f"错误: {str(e)}")
        finally:
            if conn:
                conn.close()

if __name__ == "__main__":
    # 查看文件列表
    view_files()

    # 循环删除文件
    delete_file()
