import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, abort, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Replace this key with your own secret key
SECRET_KEY = b'some_secret_key_here'

# Dictionary of allowed users and passwords
ALLOWED_USERS = {"username1": "password1", "username2": "password2"}

# Set of allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'nft'}

# Dictionary to store failed access attempts
failed_attempts = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)

    if file and allowed_file(file.filename):
        # Encrypt the file data
        encrypted_data, hash_value = encrypt_file(file)

        # Save the encrypted data to a file with custom extension
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename + '.secure')
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        return render_template('result.html', filename=filename + '.secure', hash_value=hash_value)
    else:
        return 'Invalid file type'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def encrypt_file(file):
    data = file.read()

    # Encrypt the file data
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV=b'16byteslongstring')
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    # Generate SHA-256 hash of the original file
    hasher = hashlib.sha256()
    hasher.update(data)
    hash_value = hasher.hexdigest()

    return encrypted_data, hash_value

@app.route('/download/<filename>', methods=['GET', 'POST'])
def download_file(filename):
    if request.method == 'POST':
        password = request.form.get('password')
        # Check if user is authenticated
        if not check_auth(request.remote_addr, password):
            log_failed_attempt(filename, request.remote_addr)
            return authenticate()
        # Check if file exists
        if not file_exists(filename):
            abort(404)  # Not Found
        # Serve the file
        return send_file(os.path.join('uploads', filename))
    return render_template('password.html', filename=filename)

def check_auth(ip_address, password):
    # Check if the username and password are valid
    if ip_address not in ALLOWED_USERS:
        return False
    return ALLOWED_USERS[ip_address] == password

def authenticate():
    # Return a login form with a password input field
    return render_template('password.html')

def log_failed_attempt(filename, ip_address):
    if filename not in failed_attempts:
        failed_attempts[filename] = []
    failed_attempts[filename].append(ip_address)

def file_exists(filename):
    # Check if the file exists on the server
    return os.path.exists(os.path.join('uploads', filename))

if __name__ == '__main__':
    app.run(debug=True)
