import sys
import socket
import threading
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                           QHBoxLayout, QLabel, QPushButton, QTextEdit,
                           QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from crypto_utils import CryptoUtils

class SignalHandler(QObject):
    status_update = pyqtSignal(str)
    data_received = pyqtSignal(str)

class ReceiverWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.crypto = CryptoUtils()
        self.load_keys()
        self.signal_handler = SignalHandler()
        self.signal_handler.status_update.connect(self.update_status)
        self.signal_handler.data_received.connect(self.display_data)
        self.server_socket = None
        self.client_socket = None
        self.current_mode = None
        self.current_key = None
        self.config_verified = False

    def load_keys(self):
        self.signing_public_key = self.crypto.load_rsa_key('keys/signing_rsa2048_public.pem')
        self.transport_private_key = self.crypto.load_rsa_key('keys/transport_rsa2048_private.pem')

    def init_ui(self):
        self.setWindowTitle('接收端')
        self.setGeometry(100, 100, 600, 400)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # 状态显示
        self.status_label = QLabel('状态: 等待连接')
        layout.addWidget(self.status_label)

        # 准备接收按钮
        self.ready_btn = QPushButton('准备接收数据')
        self.ready_btn.clicked.connect(self.start_server)
        self.ready_btn.setEnabled(True)
        layout.addWidget(self.ready_btn)

        # 数据显示区域
        self.data_text = QTextEdit()
        self.data_text.setReadOnly(True)
        layout.addWidget(self.data_text)

    def update_status(self, message):
        self.status_label.setText(f'状态: {message}')
        self.data_text.append(message)

    def display_data(self, data):
        self.data_text.append(f'接收到的数据:\n{data}')

    def start_server(self):
        self.ready_btn.setEnabled(False)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 22223))
        self.server_socket.listen(1)
        
        # 在新线程中处理连接
        threading.Thread(target=self.handle_connection, daemon=True).start()
        self.update_status('服务器已启动，等待连接...')

    def handle_connection(self):
        try:
            self.client_socket, addr = self.server_socket.accept()
            self.update_status(f'已连接到发送端: {addr}')
            
            # 接收加密配置包
            encrypted_config = self.client_socket.recv(4096)
            config = self.crypto.rsa_decrypt(encrypted_config, self.transport_private_key)
            
            # 接收签名
            signature = self.client_socket.recv(4096)
            
            # 验证签名
            if not self.crypto.verify_signature(config, signature, self.signing_public_key):
                self.update_status('配置包签名验证失败')
                self.client_socket.close()
                return

            # 解析配置
            mode, key = config.split('|')
            self.current_mode = mode
            self.current_key = key
            self.config_verified = True
            
            self.update_status(f'配置包验证成功\n加密模式: {mode}\n密钥: {key}')
            
            # 发送确认
            self.client_socket.send('CONFIG_OK'.encode())

            # 接收数据包
            data = self.client_socket.recv(4096)
            if data:
                self.handle_data(data)

        except Exception as e:
            self.signal_handler.status_update.emit(f'错误: {str(e)}')
        finally:
            if self.client_socket:
                self.client_socket.close()
            if self.server_socket:
                self.server_socket.close()
            self.ready_btn.setEnabled(True)

    def handle_data(self, encrypted_data):
        try:
            if not self.config_verified:
                raise Exception('配置未验证')

            # 解密数据
            if self.current_mode == 'DES':
                decrypted_data = self.crypto.des_decrypt(encrypted_data, self.current_key)
            else:
                decrypted_data = self.crypto.rc4_decrypt(encrypted_data, self.current_key)

            # 分离数据和签名
            data, signature = decrypted_data.split('||')
            
            # 验证签名
            if not self.crypto.verify_signature(data, signature, self.signing_public_key):
                self.update_status('数据签名验证失败')
                return

            self.update_status('数据签名验证成功')
            self.display_data(data)

        except Exception as e:
            self.update_status(f'处理数据失败: {str(e)}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ReceiverWindow()
    window.show()
    sys.exit(app.exec_()) 