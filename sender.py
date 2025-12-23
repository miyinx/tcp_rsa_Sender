import sys
import socket
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                           QHBoxLayout, QLabel, QLineEdit, QPushButton,
                           QComboBox, QTextEdit, QMessageBox)
from PyQt5.QtCore import Qt
from crypto_utils import CryptoUtils

class SenderWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.crypto = CryptoUtils()
        self.load_keys()
        self.socket = None
        self.connected = False

    def load_keys(self):
        self.signing_private_key = self.crypto.load_rsa_key('keys/signing_rsa2048_private.pem')
        self.transport_public_key = self.crypto.load_rsa_key('keys/transport_rsa2048_public.pem')

    def init_ui(self):
        self.setWindowTitle('发送端')
        self.setGeometry(100, 100, 600, 400)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # 加密模式选择
        mode_layout = QHBoxLayout()
        mode_label = QLabel('加密模式:')
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(['DES', 'RC4'])
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        layout.addLayout(mode_layout)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_label = QLabel('加密密钥:')
        self.key_input = QLineEdit()
        self.key_input.setText('12345678')
        self.key_input.setMaxLength(8)
        generate_key_btn = QPushButton('随机生成密钥')
        generate_key_btn.clicked.connect(self.generate_key)
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_input)
        key_layout.addWidget(generate_key_btn)
        layout.addLayout(key_layout)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.send_config_btn = QPushButton('发送配置包')
        self.send_config_btn.clicked.connect(self.send_config)
        self.send_data_btn = QPushButton('发送密文')
        self.send_data_btn.clicked.connect(self.send_data)
        self.send_data_btn.setEnabled(False)
        btn_layout.addWidget(self.send_config_btn)
        btn_layout.addWidget(self.send_data_btn)
        layout.addLayout(btn_layout)

        # 状态显示
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)

    def generate_key(self):
        if self.mode_combo.currentText() == 'DES':
            key = self.crypto.generate_des_key()
        else:
            key = self.crypto.generate_rc4_key()
        self.key_input.setText(key)

    def connect_to_receiver(self):
        if not self.connected:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect(('localhost', 22223))
                self.connected = True
                self.status_text.append('已连接到接收端')
            except Exception as e:
                QMessageBox.critical(self, '错误', f'连接失败: {str(e)}')
                return False
        return True

    def send_config(self):
        if not self.connect_to_receiver():
            return

        try:
            # 准备配置包
            config = f"{self.mode_combo.currentText()}|{self.key_input.text()}"
            # 计算配置包的SHA1值
            config_sha1 = self.crypto.calculate_sha1(config)
            signature = self.crypto.sign_data(config, self.signing_private_key)
            
            # 打印详细信息
            self.status_text.append(f'配置包明文: {config}')
            self.status_text.append(f'配置包SHA1值: {config_sha1}')
            self.status_text.append(f'配置包签名值: {signature.decode()}')
            
            # RSA加密配置包（只加密config，不拼接签名）
            encrypted_config = self.crypto.rsa_encrypt(config, self.transport_public_key)
            
            # 发送加密后的配置包
            self.socket.send(encrypted_config)
            # 发送签名
            self.socket.send(signature)
            
            # 等待确认
            response = self.socket.recv(1024).decode()
            if response == 'CONFIG_OK':
                self.status_text.append('配置包发送成功，等待发送数据...')
                self.send_data_btn.setEnabled(True)
            else:
                raise Exception('接收端拒绝配置包')
                
        except Exception as e:
            QMessageBox.critical(self, '错误', f'发送配置包失败: {str(e)}')
            self.connected = False
            if self.socket:
                self.socket.close()

    def send_data(self):
        try:
            # 读取文件内容
            with open('data.txt', 'r', encoding='utf-8') as f:
                data = f.read()

            # 签名数据
            signature = self.crypto.sign_data(data, self.signing_private_key)
            data_block = f"{data}||{signature.decode()}"

            # 加密数据
            if self.mode_combo.currentText() == 'DES':
                encrypted_data = self.crypto.des_encrypt(data_block, self.key_input.text())
            else:
                encrypted_data = self.crypto.rc4_encrypt(data_block, self.key_input.text())

            # 发送数据
            self.socket.send(encrypted_data)
            self.status_text.append('数据发送完成')

        except Exception as e:
            QMessageBox.critical(self, '错误', f'发送数据失败: {str(e)}')
        finally:
            if self.socket:
                self.socket.close()
            self.connected = False
            self.send_data_btn.setEnabled(False)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SenderWindow()
    window.show()
    sys.exit(app.exec_()) 