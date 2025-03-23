from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)

# ฟังก์ชันสำหรับสร้างคู่คีย์
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# ฟังก์ชันสำหรับเข้ารหัสข้อความ
def encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# ฟังก์ชันสำหรับถอดรหัสข้อความ
def decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# API สำหรับสร้างคู่คีย์
@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    private_key, public_key = generate_key_pair()
    # แปลงคีย์เป็นรูปแบบ PEM เพื่อส่งให้ผู้ใช้
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return jsonify({'private_key': private_pem, 'public_key': public_pem})

# API สำหรับเข้ารหัสข้อความ
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data['message']
    public_key_pem = data['public_key']
    # โหลด Public Key จาก PEM
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted_message = encrypt_message(message, public_key)
    return jsonify({'encrypted_message': encrypted_message.hex()})

# API สำหรับถอดรหัสข้อความ
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_message_hex = data['encrypted_message']
    private_key_pem = data['private_key']
    # โหลด Private Key จาก PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    encrypted_message = bytes.fromhex(encrypted_message_hex)
    decrypted_message = decrypt_message(encrypted_message, private_key)
    return jsonify({'decrypted_message': decrypted_message})

if __name__ == '__main__':
    app.run(debug=True)