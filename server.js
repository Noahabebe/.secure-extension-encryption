const express = require('express');
const multer = require('multer');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const fs = require('fs');
const crypto = require('crypto');
const mime = require('mime-types');
const path = require('path');
const os = require('os');
const app = express();
const PORT = process.env.PORT || 3001;

// Set up middleware for file upload
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Define the base directory for encrypted and decrypted files in the user's Downloads folder
const BASE_DOWNLOADS_DIR = path.join(os.homedir(), 'Downloads');

// Define the directories for encrypted and decrypted files
const ENCRYPTED_FILES_DIR = path.join(BASE_DOWNLOADS_DIR, 'EncryptedFiles');
const DECRYPTED_FILES_DIR = path.join(BASE_DOWNLOADS_DIR, 'DecryptedFiles');

// Ensure that the directories exist
if (!fs.existsSync(ENCRYPTED_FILES_DIR)) {
    fs.mkdirSync(ENCRYPTED_FILES_DIR, { recursive: true });
}
if (!fs.existsSync(DECRYPTED_FILES_DIR)) {
    fs.mkdirSync(DECRYPTED_FILES_DIR, { recursive: true });
}
const base32 = require('hi-base32');

// Function to encrypt file data with a base32 encoded secret
function encryptFile(data, secret) {
    // Decode the base32 encoded secret
    const secretBuffer = base32.decode.asBuffer(secret);
    const key = crypto.createHash('sha256').update(secretBuffer).digest('base64').substr(0, 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    const encryptedData = Buffer.concat([iv, cipher.update(data), cipher.final()]);
    return encryptedData;
}

// Function to decrypt file data with a base32 encoded secret
function decryptFile(data, secret) {
    // Decode the base32 encoded secret
    const secretBuffer = base32.decode.asBuffer(secret);
    const key = crypto.createHash('sha256').update(secretBuffer).digest('base64').substr(0, 32);
    const iv = data.slice(0, 16);
    const encryptedData = data.slice(16);
    const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    const decryptedData = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    return decryptedData;
}

// Render the file upload form
app.get('/', (req, res) => {
    res.render('upload');
});

// Handle file encryption
app.post('/encrypt', upload.single('file'), async (req, res) => {
    try {
        // Generate a secret
        const secret = base32.encode(crypto.randomBytes(20));

        
        // Access the uploaded file's buffer and original name
        const fileBuffer = req.file.buffer;
        const originalName = req.file.originalname;
        
        // Encrypt the uploaded file buffer
        const encryptedData = encryptFile(fileBuffer, secret);

        // Save the encrypted data (including secret) to a file
        const encryptedFilePath = path.join(ENCRYPTED_FILES_DIR, originalName + '.enc');
        fs.writeFileSync(encryptedFilePath, encryptedData);

        // Generate QR code for the secret
        const otpAuthUrl = authenticator.keyuri('user@example.com', 'Example', secret);
        const qrCodeUrl = await QRCode.toDataURL(otpAuthUrl);

        // Render success page with download link and QR code
        res.render('success', { downloadLink: '/download/' + encodeURIComponent(originalName + '.enc'), qrCode: qrCodeUrl });
    } catch (error) {
        console.error('Error processing file upload:', error);
        res.status(500).send('Error processing file upload');
    }
});


// Handle file decryption
app.post('/decrypt', upload.single('file'), async (req, res) => {
    try {
        // Check if a file was uploaded
        if (!req.file) {
            throw new Error('No file uploaded with the request');
        }

        // Check file extension to ensure it's an encrypted file
        const originalName = req.file.originalname;
        if (!originalName.endsWith('.enc')) {
            throw new Error('Invalid file format. Only encrypted files (.enc) are supported for decryption.');
        }

        // Access the uploaded file's buffer
        const fileBuffer = req.file.buffer;

        // Extract the secret from the file
        const secretLength = 64; // Assuming secret length is fixed
        const secret = fileBuffer.slice(0, secretLength).toString('utf8');

        // Check if the secret is base32 encoded
        if (!isBase32Encoded(secret)) {
            throw new Error('Invalid secret format. Secret must be base32 encoded.');
        }

        // Extract the OTP code from the request body
        const otpCode = req.body.token;
        
        // Check if otpCode is defined and not empty
        if (!otpCode || otpCode.trim() === '') {
            throw new Error('OTP code is missing or empty');
        }

        // Verify OTP code
        const isValidOTP = authenticator.verify({ token: otpCode, secret });
        if (!isValidOTP) {
            throw new Error('Invalid OTP code');
        }

        // Decrypt the data (excluding secret)
        const decryptedData = decryptFile(fileBuffer.slice(secretLength), secret);

        // Write decrypted data to file
        const decryptedFileName = originalName.slice(0, -4); // Remove '.enc' from the filename
        const decryptedFilePath = path.join(DECRYPTED_FILES_DIR, decryptedFileName);
        fs.writeFileSync(decryptedFilePath, decryptedData);

        // Render success page with download link
        res.render('success-decrypt', { downloadLink: '/download-decrypted/' + encodeURIComponent(decryptedFileName) });
    } catch (error) {
        console.error('Error decrypting file:', error.message);
        res.status(500).send(error.message);
    }
});

// Function to check if a string is base32 encoded
function isBase32Encoded(str) {
    const base32Regex = /^[A-Z2-7]+=*$/;
    return base32Regex.test(str);
}


// Serve encrypted file for download
app.get('/download/:filename', (req, res) => {
    const encryptedFilePath = path.join(ENCRYPTED_FILES_DIR, req.params.filename);

    // Send the file as an attachment
    res.download(encryptedFilePath);
});

// Serve decrypted file for download
app.get('/download-decrypted/:filename', (req, res) => {
    const decryptedFilePath = path.join(DECRYPTED_FILES_DIR, req.params.filename);

    // Send the file as an attachment
    res.download(decryptedFilePath);
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
