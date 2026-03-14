const { generateKeyPairSync } = require('crypto');
const fs = require('fs');
const path = require('path');

// Thư mục hiện tại (keys)
const keysDir = __dirname;

// Tạo key pair RSA
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
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

// Lưu key vào file trong thư mục keys
fs.writeFileSync(path.join(keysDir, 'private.pem'), privateKey);
fs.writeFileSync(path.join(keysDir, 'public.pem'), publicKey);

console.log('RSA keys generated successfully!');
console.log('Private key saved to:', path.join(keysDir, 'private.pem'));
console.log('Public key saved to:', path.join(keysDir, 'public.pem'));
