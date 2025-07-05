import os
import sys
import glob
import socket
import threading
from queue import Queue
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QPoint
import xml.etree.ElementTree as ET
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QTextEdit, QPushButton, QLabel, QMessageBox, QComboBox, QStackedLayout, QFrame, QScrollArea

def read_student_file():
    base_dir = r"C:\Users\Public\Documents\极域课堂管理系统软件v*.* *\*\Class Data"
    cls_files = glob.glob(os.path.join(base_dir, "*.cls"), recursive=True)
    all_classes = []

    for cls_file in cls_files:
        try:
            tree = ET.parse(cls_file)
            root = tree.getroot()
            classes = [os.path.splitext(os.path.basename(cls_file))[0]]
            for student in root.findall(".//student"):
                name_elem = student.find("name")
                address_elem = student.find("address")
                if name_elem is not None and address_elem is not None:
                    ip = address_elem.attrib.get("IP", "")
                    classes.append({"name": name_elem.text, "ip": ip})
            all_classes.append(classes)
        except Exception:
            continue

    return all_classes

def get_local_ips():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        ip_parts = local_ip.split('.')
        base_ip = '.'.join(ip_parts[:3]) + '.'
        return [base_ip + str(i) for i in range(1, 255)]
    except Exception:
        # 兼容部分主机名无法直接获取IP的情况
        return []

def check_special_packet(ip, port, result_list):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.sendto("SPECIAL_SCAN".encode('utf-8'), (ip, port))
            data, addr = sock.recvfrom(1024)
            if data.decode('utf-8') == "SPECIAL_RESPONSE":
                result_list.append(ip)
    except socket.timeout:
        pass
    except Exception:
        pass

def worker(queue, port, result_list):
    while not queue.empty():
        ip = queue.get()
        check_special_packet(ip, port, result_list)
        queue.task_done()

class UDPClientGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("")
        self.resize(600, 500)
        self.target_ip = ""
        self.target_port = 25555
        self.udp_socket = None
        self.is_expanded = False
        self.all_classes = read_student_file()

        # 隐藏原生标题栏
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)

        self._old_pos = None  # 用于窗口拖动

        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # 左侧主页面
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setSpacing(0)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # 自定义标题栏
        title_bar = QHBoxLayout()
        title_bar.setSpacing(0)
        title_bar.setContentsMargins(0, 0, 0, 0)

        self.title_label = QLabel(" 教师控制端 ")
        self.title_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #3576e6; padding: 6px 0 6px 12px;")
        title_bar.addWidget(self.title_label)

        title_bar.addStretch()

        # 最小化按钮
        self.min_btn = QPushButton("—")
        self.min_btn.setFixedSize(32, 28)
        self.min_btn.setStyleSheet("""
    QPushButton {
        border: none;
        font-size: 18px;
        padding-bottom: 10px;
    }
    QPushButton:hover {
        background: #e3e9f6;
    }
""")
        self.min_btn.clicked.connect(self.showMinimized)
        title_bar.addWidget(self.min_btn)

        # 关闭按钮
        self.close_btn = QPushButton("✕")
        self.close_btn.setFixedSize(32, 28)
        self.close_btn.setStyleSheet("""
    QPushButton {
        border: none;
        font-size: 18px;
        padding-bottom: 10px;
    }
    QPushButton:hover {
        background: #ff4c4c;
        color: white;
    }
""")
        self.close_btn.clicked.connect(self.close)
        title_bar.addWidget(self.close_btn)

        left_layout.addLayout(title_bar)

        # 其余控件布局（原有内容）
        content_layout = QVBoxLayout()
        content_layout.setSpacing(18)
        content_layout.setContentsMargins(32, 32, 32, 32)

        self.ip_label = QLabel("目标IP地址:")
        self.ip_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #222;")
        content_layout.addWidget(self.ip_label)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("请输入目标IP")
        content_layout.addWidget(self.ip_input)

        self.handshake_btn = QPushButton("握手连接")
        content_layout.addWidget(self.handshake_btn)

        self.scan_btn = QPushButton("扫描局域网")
        content_layout.addWidget(self.scan_btn)

        self.status_label = QLabel("未连接")
        self.status_label.setStyleSheet("font-size: 14px; color: #888;")
        content_layout.addWidget(self.status_label)

        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("输入消息 ('1' 关机, '2' 重启极域, '3 <进程名称>'可以关闭目标机的特定进程。其他作为cmd命令发送)")
        content_layout.addWidget(self.msg_input)

        self.send_btn = QPushButton("发送消息")
        content_layout.addWidget(self.send_btn)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        content_layout.addWidget(self.output)

        left_layout.addLayout(content_layout)

        # 右上角扩展按钮
        self.expand_btn = QPushButton("⇔")
        self.expand_btn.setFixedSize(36, 36)
        self.expand_btn.setStyleSheet("font-size:20px; border:none;")
        self.expand_btn.clicked.connect(self.toggle_expand)
        # 放到主页面右上角
        title_bar.insertWidget(title_bar.count()-2, self.expand_btn)  # 放到最小化按钮左侧

        # 右侧扩展页面
        self.expand_widget = QFrame()
        self.expand_widget.setFixedWidth(320)
        self.expand_widget.setFrameShape(QFrame.StyledPanel)
        expand_layout = QVBoxLayout(self.expand_widget)
        expand_layout.setContentsMargins(16, 16, 16, 16)
        expand_layout.setSpacing(12)

        # 下拉选择框
        self.class_combo = QComboBox()
        self.class_combo.addItems([c[0] for c in self.all_classes])
        self.class_combo.currentIndexChanged.connect(self.update_student_list)
        expand_layout.addWidget(self.class_combo)

        # 学生列表区域（可滚动）
        self.student_area = QScrollArea()
        self.student_area.setWidgetResizable(True)
        self.student_list_widget = QWidget()
        self.student_list_layout = QVBoxLayout(self.student_list_widget)
        self.student_list_layout.setAlignment(Qt.AlignTop)
        self.student_area.setWidget(self.student_list_widget)
        expand_layout.addWidget(self.student_area)

        # 默认隐藏扩展页
        self.expand_widget.setVisible(False)

        # 主体布局
        main_layout.addWidget(left_widget)
        main_layout.addWidget(self.expand_widget)

        self.setLayout(main_layout)
        self.update_student_list(0)  # 初始化学生列表

        # 连接信号
        self.handshake_btn.clicked.connect(self.do_handshake)
        self.scan_btn.clicked.connect(self.scan_network)
        self.send_btn.clicked.connect(self.send_message)
        self.send_btn.setEnabled(False)

        # Win11风格QSS
        self.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #f6f8fc, stop:1 #e3e9f6);
                border-radius: 18px;
                font-family: 'Segoe UI', 'Microsoft YaHei', Arial;
            }
            QLineEdit, QTextEdit {
                background: #fff;
                border: 1.5px solid #c3cfe2;
                border-radius: 10px;
                padding: 8px;
                font-size: 15px;
                color: #222;
            }
            QLineEdit:focus, QTextEdit:focus {
                border: 1.5px solid #4f8cff;
                background: #f0f6ff;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #4f8cff, stop:1 #3576e6);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 10px 0;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #3576e6, stop:1 #4f8cff);
            }
            QLabel {
                font-size: 15px;
            }
        """)

    def do_handshake(self):
        self.target_ip = self.ip_input.text().strip()
        if not self.target_ip:
            QMessageBox.warning(self, "错误", "请输入目标IP地址")
            return

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        handshake_message = "HANDSHAKE"
        retry = 0
        success = False
        self.output.append(f"发送握手包到 {self.target_ip}:{self.target_port}，等待回应...")

        while retry < 3:
            try:
                self.udp_socket.settimeout(2)
                self.udp_socket.sendto(handshake_message.encode('utf-8'), (self.target_ip, self.target_port))
                data, addr = self.udp_socket.recvfrom(1024)
                if data.decode('utf-8') == "HANDSHAKE_ACK":
                    self.output.append(f"握手成功，已连接到 {addr}")
                    self.status_label.setText(f"已连接到 {addr}")
                    success = True
                    self.send_btn.setEnabled(True)
                    break
                else:
                    self.output.append("握手失败，收到无效回应。")
            except socket.timeout:
                retry += 1
                self.output.append(f"握手超时，重试第{retry}次...")
        if not success:
            self.output.append("多次握手失败，请重新输入IP地址。")
            self.status_label.setText("未连接")
            self.send_btn.setEnabled(False)
            self.udp_socket.close()
            self.udp_socket = None

    def  send_message(self):
        if not self.udp_socket:
            QMessageBox.warning(self, "错误", "请先握手连接")
            return

        message = self.msg_input.text().strip()
        if not message:
            return

        if message == "1":
            send_msg = "shutdown -s -t 1"
        elif message == "2":
            send_msg = "RESTART_STUDENTMAIN"
        elif message.startswith("3 "):
            send_msg = "taskkill /f /im " + message[2:] + " /t"
        else:
            send_msg = message

        self.udp_socket.sendto(send_msg.encode('utf-8'), (self.target_ip, self.target_port))
        self.output.append(f"消息已发送: {send_msg}")
        try:
            self.udp_socket.settimeout(1)
            data, addr = self.udp_socket.recvfrom(1024)
            self.output.append(f"收到来自 {addr} 的回复: {data.decode('utf-8')}")
        except socket.timeout:
            pass

    def scan_network(self):
        self.output.append("开始扫描局域网，请稍候...")
        self.scan_btn.setEnabled(False)
        self.output.repaint()

        port = self.target_port
        result_list = []
        ip_queue = Queue()
        ips = get_local_ips()
        if not ips:
            self.output.append("无法获取本地IP段，扫描失败。")
            self.scan_btn.setEnabled(True)
            return

        for ip in ips:
            ip_queue.put(ip)

        threads = []
        for _ in range(50):
            thread = threading.Thread(target=worker, args=(ip_queue, port, result_list))
            thread.start()
            threads.append(thread)

        # 等待所有任务完成
        ip_queue.join()
        for thread in threads:
            thread.join()

        if result_list:
            self.output.append("响应特殊包的IP地址：")
            for ip in result_list:
                self.output.append(ip)
        else:
            self.output.append("未发现在线客户端。")
        self.scan_btn.setEnabled(True)

    def toggle_expand(self):
        self.is_expanded = not self.is_expanded
        self.expand_widget.setVisible(self.is_expanded)
        if self.is_expanded:
            self.resize(self.width() + self.expand_widget.width(), self.height())
        else:
            self.resize(self.width() - self.expand_widget.width(), self.height())

    def update_student_list(self, idx):
        # 清空旧的学生按钮
        for i in reversed(range(self.student_list_layout.count())):
            widget = self.student_list_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        # 添加新学生按钮
        if idx < len(self.all_classes):
            for stu in self.all_classes[idx][1:]:
                btn = QPushButton(stu["name"])
                btn.setStyleSheet("text-align:left; font-size:15px;")
                btn.clicked.connect(lambda _, s=stu: self.connect_student(s))
                self.student_list_layout.addWidget(btn)

    def connect_student(self, stu):
        # 自动填充IP并握手
        self.ip_input.setText(stu["ip"])
        self.do_handshake()

    # 实现窗口拖动
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and event.pos().y() < 40:
            self._old_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._old_pos and event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self._old_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._old_pos = None

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = UDPClientGUI()
    window.show()
    sys.exit(app.exec_())