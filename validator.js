const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
let userController = require("../controllers/users");

// Đọc RSA private key và public key
const privateKeyPath = path.join(__dirname, '../keys/private.pem');
const publicKeyPath = path.join(__dirname, '../keys/public.pem');

let privateKey = '';
let publicKey = '';

try {
    privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    publicKey = fs.readFileSync(publicKeyPath, 'utf8');
} catch (error) {
    console.error('Error reading RSA keys:', error.message);
}

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith('Bearer')) {
                res.status(404).send("ban chua dang nhap")
            }
            token = token.split(" ")[1];
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            if (result.exp * 1000 > Date.now()) {
                let user = await userController.FindUserById(result.id);
                if (user) {
                    req.user = user
                    next()
                } else {
                    res.status(404).send("ban chua dang nhap")
                }
            } else {
                res.status(404).send("ban chua dang nhap")
            }
        } catch (error) {
            res.status(404).send("ban chua dang nhap")
        }
    },
    signToken: function (payload) {
        return jwt.sign(payload, privateKey, { expiresIn: '1h', algorithm: 'RS256' });
    },
    getPublicKey: function () {
        return publicKey;
    },
    getPrivateKey: function () {
        return privateKey;
    }
}