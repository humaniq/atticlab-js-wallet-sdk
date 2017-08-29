/* * Copyright 2017 Atticlab LLC.
 * Licensed under the Apache License, Version 2.0
 * See the LICENSE or LICENSE_UA file at the root of this repository
 * Contact us at http://atticlab.net
 */

const _ = require('lodash');
const sjcl = require('sjcl');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');

require('sjcl-scrypt').extendSjcl(sjcl);

class Crypto {

    cyclicHash(key, algorithm, rounds, cb) {
        return new Promise(resolve => {
            var c = 0;
            var iterations_per_round = Math.floor(rounds / 100) || rounds;

            var makeHash = function () {
                for (var b = 0; b < iterations_per_round; b++) {
                    c++

                    key = sjcl.hash[algorithm].hash(key);
                    if (c >= rounds) {
                        break;
                    }
                }

                if (typeof cb == 'function') {
                    cb(c);
                }

                if (c >= rounds) {
                    return resolve(key);
                }

                return setTimeout(makeHash, 10);
            }

            makeHash();
        })
    }

    scrypt(password, salt, kdf_params) {
        return new Promise(resolve => {
            var key = sjcl.misc.scrypt(
                password,
                sjcl.hash.sha256.hash(salt),
                kdf_params.n,
                kdf_params.r,
                kdf_params.p,
                kdf_params.bits / 8
            );

            resolve(key);
        });
    }

    base64Encode(str) {
        return (new Buffer(str)).toString('base64');
    }

    base64Decode(str) {
        return (new Buffer(str, 'base64')).toString();
    }

    deriveWalletId(msg) {
        return this.hmacEncrypt(msg, 'WALLET_ID');
    }

    deriveWalletKey(msg) {
        return this.hmacEncrypt(msg, 'WALLET_KEY');
    }

    hmacEncrypt(msg, key) {
        var hmac = new sjcl.misc.hmac(msg, sjcl.hash.sha256);
        return hmac.encrypt(key);
    }

    encryptData(data, key) {
        if (!_.isString(data)) {
            throw new TypeError('data must be a String.');
        }

        const cipherName = 'aes';
        const modeName = 'gcm';

        let cipher = new sjcl.cipher[cipherName](key);
        let rawIV = sjcl.random.randomWords(3);
        let encryptedData = sjcl.mode[modeName].encrypt(
            cipher,
            sjcl.codec.utf8String.toBits(data),
            rawIV
        );

        data = JSON.stringify({
            IV: sjcl.codec.base64.fromBits(rawIV),
            cipherText: sjcl.codec.base64.fromBits(encryptedData),
            cipherName: cipherName,
            modeName: modeName
        });

        return this.base64Encode(data);
    }

    decryptData(encryptedData, key) {
        let rawCipherText, rawIV, cipherName, modeName;

        let resultObject = JSON.parse(this.base64Decode(encryptedData));
        rawIV = sjcl.codec.base64.toBits(resultObject.IV);
        rawCipherText = sjcl.codec.base64.toBits(resultObject.cipherText);
        cipherName = resultObject.cipherName;
        modeName = resultObject.modeName;

        let cipher = new sjcl.cipher[cipherName](key);
        let rawData = sjcl.mode[modeName].decrypt(cipher, rawCipherText, rawIV);
        return sjcl.codec.utf8String.fromBits(rawData);
    }

    signMessage(message, key) {
        return this.base64Encode(nacl.sign.detached(nacl.util.decodeUTF8(message), key));
    }
}

module.exports = new Crypto