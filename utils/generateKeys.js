const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const keysDir = path.join(__dirname, '../keys');

// Tạo thư mục keys nếu chưa tồn tại
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
}

const privateKeyPath = path.join(keysDir, 'private.key');
const publicKeyPath = path.join(keysDir, 'public.key');

// Nếu keys đã tồn tại, không cần tạo lại
if (fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath)) {
    console.log('RSA keys already exist');
} else {
    // Generate RSA key pair
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    // Lưu private key
    fs.writeFileSync(privateKeyPath, privateKey);
    console.log('Private key saved to', privateKeyPath);

    // Lưu public key
    fs.writeFileSync(publicKeyPath, publicKey);
    console.log('Public key saved to', publicKeyPath);
}

module.exports = {
    privateKey: fs.readFileSync(privateKeyPath, 'utf-8'),
    publicKey: fs.readFileSync(publicKeyPath, 'utf-8')
};
