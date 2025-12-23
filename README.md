# tcp_rsa_Sender
基于TCP与RSA的发送端与接收端。网络安全课设。


这是一个基于TCP的安全通信系统，实现了数据加密传输和数字签名认证功能，一次一密等。

## 功能特点

- 支持DES和RC4两种加密模式
- 使用RSA进行密钥传输和数字签名
- 提供图形用户界面
- 实现了完整的安全通信流程

## 系统要求

- Python 3.6+
- PyQt5
- pycryptodome

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

1. 确保`keys`目录中包含所需的RSA密钥文件：
   - signing_rsa2048_private.pem
   - signing_rsa2048_public.pem
   - transport_rsa2048_private.pem
   - transport_rsa2048_public.pem

2. 在项目根目录创建`data.txt`文件，将要传输的数据写入其中。

3. 分别启动发送端和接收端：
   ```bash
   # 启动接收端
   python receiver.py
   
   # 启动发送端
   python sender.py
   ```

4. 使用步骤：
   - 在接收端点击"准备接收数据"按钮
   - 在发送端选择加密模式（DES或RC4）
   - 输入或生成加密密钥
   - 点击"发送配置包"按钮
   - 等待配置包验证成功后，点击"发送密文"按钮

## 通信流程

1. 配置包传输：
   - 发送端使用RSA传输公钥加密配置包
   - 接收端使用RSA传输私钥解密配置包
   - 使用RSA签名验证配置包的完整性

2. 数据传输：
   - 发送端使用选择的加密算法（DES/RC4）加密数据
   - 接收端使用对应的解密算法解密数据
   - 使用RSA签名验证数据的完整性

## 注意事项

- 确保密钥文件的安全性
- 发送端和接收端需要在同一网络环境下
- 默认使用localhost进行通信
- 发送端端口：22222
- 接收端端口：22223 
