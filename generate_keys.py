from Crypto.PublicKey import RSA
import os

def generate_rsa_key_pair(filename_prefix):
    # 生成2048位的RSA密钥对
    key = RSA.generate(2048)
    
    # 确保keys目录存在
    if not os.path.exists('keys'):
        os.makedirs('keys')
    
    # 保存私钥
    with open(f'keys/{filename_prefix}_private.pem', 'wb') as f:
        f.write(key.export_key('PEM'))
    
    # 保存公钥
    with open(f'keys/{filename_prefix}_public.pem', 'wb') as f:
        f.write(key.publickey().export_key('PEM'))

def main():
    # 生成签名密钥对
    generate_rsa_key_pair('signing_rsa2048')
    
    # 生成传输密钥对
    generate_rsa_key_pair('transport_rsa2048')
    
    print("RSA密钥对已生成在keys目录中：")
    print("- signing_rsa2048_private.pem")
    print("- signing_rsa2048_public.pem")
    print("- transport_rsa2048_private.pem")
    print("- transport_rsa2048_public.pem")

if __name__ == '__main__':
    main()