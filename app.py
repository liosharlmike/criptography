from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# AES Encryption
def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

# AES Decryption
def decrypt_aes(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    plaintext = data['plaintext']
    key = get_random_bytes(16)  # 128-bit key
    iv, ciphertext = encrypt_aes(plaintext, key)
    return jsonify({'iv': iv, 'ciphertext': ciphertext, 'key': base64.b64encode(key).decode('utf-8')})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    iv = data['iv']
    ciphertext = data['ciphertext']
    key = base64.b64decode(data['key'])
    plaintext = decrypt_aes(iv, ciphertext, key)
    return jsonify({'plaintext': plaintext})

if __name__ == '__main__':
    app.run(debug=True)