/* * Copyright 2017 Atticlab LLC.
 * Licensed under the Apache License, Version 2.0
 * See the LICENSE or LICENSE_UA file at the root of this repository
 * Contact us at http://atticlab.net
 */

const EventEmitter = require('events').EventEmitter;
const StellarSdk = require('js-sdk');
const _ = require('lodash');
const axios = require('axios');
const nacl = require('tweetnacl');
const sjcl = require('sjcl');
const Wallet = require('./wallet');
const crypto = require('./crypto');
const errors = require('./errors');
const qs = require('qs');
const bad_passwords = require('./bad_passwords');

var cached_kdf_params;

module.exports = class extends EventEmitter {
    constructor(options) {
        super();

        var self = this;

        if (typeof options.host == undefined) {
            throw new Error('host is not set');
        }

        this.options = Object.assign({}, {
            // Ttl for api requests
            request_ttl: 10,

            // Enable debug mode
            debug: false,
        }, options);

        this.axios = axios.create();
        this.axios.defaults.baseURL = this.options.host.replace(/\/+$/g, '');
        this.axios.defaults.timeout = this.options.request_ttl * 1000;
        this.axios.defaults.paramsSerializer = function (params) {
            return Qs.stringify(params, {
                arrayFormat: 'brackets'
            })
        }

        this.axios.interceptors.request.use(function (config) {
            if (typeof config.signRequest == 'function') {
                let nonce = typeof config.nonce != 'undefined' ? config.nonce : '';
                let route = config.url.replace(/^(https?:)?(\/{2})?.*?(?=\/)/, '');
                if (typeof config.params == 'object' && Object.keys(config.params).length) {
                    route += (route.indexOf('?') === -1 ? '?' : '&') + qs.stringify(config.params, {
                            encode: false,
                            arrayFormat: 'brackets'
                        });
                }

                let request_data = typeof config.data == 'object' ? JSON.stringify(config.data) : '';
                let signature = config.signRequest(nonce + route + request_data)

                if (typeof config.nonce != 'undefined') {
                    config.headers['Nonce'] = nonce
                }

                config.headers['Signature'] = signature
            }


            if (self.options.debug) {
                config.headers['Debug'] = true;
            }

            return config;
        });

        this.axios.interceptors.response.use(function (response) {
            return response.data;
        }, function (error) {
            if (error.response && error.response.data) {
                return Promise.reject(errors.getProtocolError(error.response.data.error, error.response.data.message || ''));
            }

            return Promise.reject(new errors.ConnectionError());
        });
    }

    create(params) {
        var self = this;

        if (!_.isObject(params)) {
            throw new Error('params is not an object');
        }

        if (!_.isString(params.password)) {
            throw new Error('password is not set');
        }

        if (!params.keypair instanceof StellarSdk.Keypair) {
            throw new Error('keypair must be an instanceof StellarSdk.Keypair');
        }

        // check bad password
        if (bad_passwords.indexOf(params.password) > -1) {
            throw new Error('Insecure password');
        }

        if (_.isEmpty(params.phone) && _.isEmpty(params.email) && _.isEmpty(params.face_uuid)) {
            throw new Error('You need any of these keys for account: phone, email, face_uuid');
        }

        params.seed = params.keypair.secret();
        params.account_id = params.keypair.publicKey();
        params.salt = crypto.base64Encode(nacl.randomBytes(16));

        return Promise.resolve(params)
            .then(this.getKdfParams.bind(this))
            .then(this._hashPassword.bind(this))
            .then(this._calculateMasterKey.bind(this))
            .then(params => {
                let raw_wallet_id = crypto.deriveWalletId(params.raw_master_key);
                let raw_wallet_key = crypto.deriveWalletKey(params.raw_master_key);

                params.wallet_id = sjcl.codec.base64.fromBits(raw_wallet_id);
                params.keychain_data = crypto.encryptData(params.seed, raw_wallet_key);

                return self.axios.post('/wallets/create', _.pick(params, [
                        'account_id',
                        'wallet_id',
                        'keychain_data',
                        'salt',
                        'kdf_params',
                        'phone',
                        'email',
                        'face_uuid',
                    ]))
                    .then(() => {
                        return Promise.resolve(new Wallet(self, params));
                    })
            });
    }

    getKdfParams(params) {
        if (_.isObject(params.kdf_params)) {
            return Promise.resolve(params);
        }

        if (cached_kdf_params) {
            params.kdf_params = cached_kdf_params;
            return Promise.resolve(params);
        }

        return this.axios.get('/index/getkdf')
            .then(function (resp) {
                cached_kdf_params = resp;
                params.kdf_params = resp;

                return Promise.resolve(params);
            })
    }

    getNonce(params) {
        if (!_.isObject(params)) {
            throw new Error('params is not an object');
        }

        if (_.isEmpty(params.account_id)) {
            throw new Error('Params account_id is empty');
        }

        return this.axios.post('/auth/createnonce', _.pick(params, ['account_id']))
            .then(function (resp) {
                params.nonce = resp

                return Promise.resolve(params);
            });
    }

    getData(params) {
        var self = this;

        if (!_.isObject(params)) {
            throw new Error('params is not an object');
        }

        if (_.isEmpty(params.phone) && _.isEmpty(params.email) && _.isEmpty(params.face_uuid) && _.isEmpty(params.udid)) {
            throw new Error('You need any of these keys for account: phone, email, face_uuid, udid');
        }

        if (_.isEmpty(params.password) && _.isEmpty(params.password_hash)) {
            throw new Error('You need to provide "password" or "password_hash" ! ');
        }

        return this.axios.post('/wallets/getdata', _.pick(params, ['email', 'phone', 'face_uuid', 'udid']))
            .then(function (resp) {
                var p = _.extend(resp, params);
                return Promise.resolve(p);
            })
            .then(this._hashPassword.bind(this))
            .then(this._calculateMasterKey.bind(this));
    }

    get(params) {
        var self = this;

        return this.getData(params)
            .then(params => {
                let raw_wallet_id = crypto.deriveWalletId(params.raw_master_key);
                let raw_wallet_key = crypto.deriveWalletKey(params.raw_master_key);

                params.wallet_id = sjcl.codec.base64.fromBits(raw_wallet_id);
                params.raw_wallet_key = raw_wallet_key;

                // Send request
                return self.axios.post('/wallets/get', _.pick(params, [
                        'account_id',
                        'wallet_id',
                        'totp_code',
                        'sms_code'
                    ]))
                    .then(function (resp) {
                        var p = _.extend(resp, params);
                        p.seed = crypto.decryptData(p.keychain_data, p.raw_wallet_key);

                        return Promise.resolve(new Wallet(self, p));
                    });
            })
    }

    exists(params) {
        if (!_.isObject(params)) {
            throw new Error('params is not an object');
        }

        if (_.isEmpty(params.phone) && _.isEmpty(params.email) && _.isEmpty(params.face_uuid) && _.isEmpty(params.udid)) {
            throw new Error('You need any of these keys for account: phone, email, face_uuid, udid');
        }

        return this.axios.post('/wallets/exists', _.pick(params, [
            'phone',
            'email',
            'face_uuid',
            'udid',
        ]));
    }

    setPassword(params) {
        var self = this;

        if (!_.isObject(params)) {
            throw new Error('params is not an object');
        }

        if (!_.isString(params.password)) {
            throw new Error('password is not set');
        }

        if (!params.keypair instanceof StellarSdk.Keypair) {
            throw new Error('keypair must be an instanceof StellarSdk.Keypair');
        }

        // check bad password
        if (bad_passwords.indexOf(params.password) > -1) {
            throw new Error('Insecure password');
        }

        params.seed = params.keypair.secret();
        params.account_id = params.keypair.publicKey();
        params.salt = crypto.base64Encode(nacl.randomBytes(16));

        return Promise.resolve(params)
            .then(this.getNonce.bind(this))
            .then(this.getKdfParams.bind(this))
            .then(this._hashPassword.bind(this))
            .then(this._calculateMasterKey.bind(this))
            .then(params => {
                let raw_wallet_id = crypto.deriveWalletId(params.raw_master_key);
                let raw_wallet_key = crypto.deriveWalletKey(params.raw_master_key);

                params.wallet_id = sjcl.codec.base64.fromBits(raw_wallet_id);
                params.keychain_data = crypto.encryptData(params.seed, raw_wallet_key);

                return self.axios.post('/wallets/update', _.pick(params, [
                        'wallet_id',
                        'keychain_data',
                        'salt',
                        'kdf_params',
                    ]), {
                        nonce: params.nonce,
                        signRequest: function (data) {
                            return crypto.signMessage(data, params.keypair._secretKey);
                        }
                    })
                    .then(() => {
                        return Promise.resolve(new Wallet(self, params));
                    })
            });
    }

    setUDID(params) {
        var self = this;

        if (!_.isObject(params)) {
            throw new Error('params is not an object');
        }

        if (!_.isString(params.udid)) {
            throw new Error('udid is not set');
        }

        if (!params.keypair instanceof StellarSdk.Keypair) {
            throw new Error('keypair must be an instanceof StellarSdk.Keypair');
        }

        params.seed = params.keypair.secret();
        params.account_id = params.keypair.publicKey();
        params.salt = crypto.base64Encode(nacl.randomBytes(16));

        return Promise.resolve(params)
            .then(this.getNonce.bind(this))
            .then(this.getKdfParams.bind(this))
            //.then(this._hashPassword.bind(this))
            .then(this._calculateMasterKey.bind(this))
            .then(params => {
                let raw_wallet_id = crypto.deriveWalletId(params.raw_master_key);
                let raw_wallet_key = crypto.deriveWalletKey(params.raw_master_key);

                params.wallet_id = sjcl.codec.base64.fromBits(raw_wallet_id);
                params.keychain_data = crypto.encryptData(params.seed, raw_wallet_key);

                return self.axios.post('/wallets/update', _.pick(params, [
                    'wallet_id',
                    'keychain_data',
                    'salt',
                    'kdf_params',
                ]), {
                    nonce: params.nonce,
                    signRequest: function (data) {
                        return crypto.signMessage(data, params.keypair._secretKey);
                    }
                })
                    .then(() => {
                        return Promise.resolve(new Wallet(self, params));
                    })
            });
    }

    sendSms(params) {
        var self = this;
                return self.axios.post('/auth/sendSms', _.pick(params, [
                    'phone',
                ]));
    }

    checkSms(params) {
        var self = this;
        return self.axios.post('/auth/checkSms', _.pick(params, [
            'phone',
            'code',
        ]));
    }

    _hashPassword(params) {
        var self = this;

        if (!params.kdf_params.password_algorithm || !params.kdf_params.password_rounds) {
            return Promise.resolve(params);
        }

        if (params.password_hash) {
            return Promise.resolve(params);
        }

        var password = params.account_id + params.password + params.salt;

        return crypto.cyclicHash(password, params.kdf_params.password_algorithm, params.kdf_params.password_rounds, (rounds_done) => {
            self.emit('hashPasswordRound', params.kdf_params.password_rounds, rounds_done);
        }).then(hash => {
            hash = sjcl.codec.hex.fromBits(hash);

            self.emit('hashPassword', hash);
            params.password_hash = hash;

            return Promise.resolve(params);
        });
    }

    _calculateMasterKey(params) {
        let salt = _.reduce([sjcl.codec.base64.toBits(params.salt), sjcl.codec.utf8String.toBits(params.username)], sjcl.bitArray.concat);

        return crypto.scrypt(params.password_hash || params.password, salt, params.kdf_params).then(key => {
            params.raw_master_key = key;

            return Promise.resolve(params);
        });
    }

    encryptData(data, key) {
        key = crypto.hmacEncrypt(key, 'ENC_DATA')

        return crypto.encryptData(data, key);
    }

    decryptData(data, key) {
        key = crypto.hmacEncrypt(key, 'ENC_DATA')

        return crypto.decryptData(data, key);
    }
}
