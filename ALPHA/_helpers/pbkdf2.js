const crypto = require('crypto');

function hash(password) {
    const promise = new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString('hex');
        crypto.pbkdf2(password, salt, 10000, 64, 'sha512', (err, derivedKey) => {
            if(err) {
                reject(err);
                return;
            }
            resolve(`${salt}.${derivedKey.toString('hex')}`);
        });
    });
    return promise;
}

function compare(hashedPassword, password) {
    const promise = new Promise((resolve, reject) => {
        const [salt, key] = hashedPassword.split('.')
        crypto.pbkdf2(password, salt, 10000, 64, 'sha512', (err, derivedKey) => {
            if(err) {
                reject(err);
                return;
            }
            resolve(key === derivedKey.toString('hex'));
        });
    });
    return promise;
}

module.exports = {hash, compare};