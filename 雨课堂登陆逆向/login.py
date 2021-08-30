from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
import base64

def login(username,password):
    with open('ghost-public.pem')) as f:
        key = f.read()
        pub_key = RSA.importKey(str(key))
        cipher = PKCS1_cipher.new(pub_key)
        rsa_text = base64.b64encode(cipher.encrypt(bytes(password.encode("utf8"))))
        password = rsa_text.decode('utf-8')

    payload = {"type": "PP", "name": username, "pwd": password}
    payload = json.dumps(payload)
    url = "https://www.yuketang.cn/pc/login/verify_pwd_login"
    headers = {
        "Content-Type": "application/json",
    }
    res = requests.request("POST", url, headers = headers, data = payload)

if __name__ == '__main__':
    login(username,password)
