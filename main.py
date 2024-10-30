from flask import Flask, request, render_template, redirect, url_for
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import io
import base64

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploaded_photos'
app.config['ENCRYPTED_FOLDER'] = 'encrypted_photos'

# Function to encrypt a file
def encrypt_file(file_path):
    key = b'0123456789abcdef'  # Static key
    iv = os.urandom(16)        # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Save the encrypted file
    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], os.path.basename(file_path))
    with open(encrypted_path, 'wb') as f:
        f.write(iv + ciphertext)  # Save iv with the encrypted text

    return encrypted_path

# Function to decrypt a file
def decrypt_file(file_path):
    key = b'0123456789abcdef'  # Static key
    with open(file_path, 'rb') as f:
        iv = f.read(16)  # Read iv
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_photo():
    message = None
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)  # Save the image
            encrypt_file(file_path)  # Encrypt the image
            message = "Photo uploaded and encrypted successfully!"
    return render_template('encrypt.html', message=message)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_photo():
    decrypted_image = None
    message = None

    if request.method == 'POST':
        filename = request.form['filename']
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)

        if os.path.exists(encrypted_path):
            # Decrypt the image
            decrypted_data = decrypt_file(encrypted_path)
            
            # Convert decrypted data to base64 for HTML display
            decrypted_image = base64.b64encode(decrypted_data).decode('utf-8')
        else:
            message = "Decryption failed. Make sure the filename is correct."

    return render_template('decrypt.html', decrypted_image=decrypted_image, message=message)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Ensure the uploaded images folder exists
    os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)  # Ensure the encrypted images folder exists
    app.run(debug=True)
