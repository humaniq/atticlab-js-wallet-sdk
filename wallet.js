/* * Copyright 2017 Atticlab LLC.
 * Licensed under the Apache License, Version 2.0
 * See the LICENSE or LICENSE_UA file at the root of this repository
 * Contact us at http://atticlab.net
 */

const StellarSdk = require('js-sdk');
const _ = require('lodash');
const sjcl = require('sjcl');
const crypto = require('./crypto');


class Wallet {
    constructor(api, p) {
        var params = _.cloneDeep(p);

        this.api = api;

        this.wallet_id = params.wallet_id;
        this.account_id = params.account_id;
        this.seed = params.seed;
        this.phone = params.phone;
        this.email = params.email;
        this.face_uuid = params.face_uuid;
        this.is_totp_enabled = params.is_totp_enabled;
    }

    getNonce() {
        return this.api.axios.post('/auth/createnonce', _.pick(this, ['account_id']))
    }

    enableTotp() {
        var self = this;

        return this.getNonce()
            .then(nonce => {
                return this.api.axios.post('/auth/enableTotp', {}, {
                    nonce: nonce,
                    signRequest: self.sign.bind(this)
                });
            })
    }

    activateTotp(code) {
        var self = this;

        if (_.isUndefined(code)) {
            throw new TypeError('code is not isset.');
        }

        return this.api.axios.post('/auth/activateTotp', {
            account_id: this.account_id,
            totp_code: code
        }).then(() => {
            self.is_totp_enabled = true;
        })
    }

    disableTotp() {
        var self = this;

        return this.getNonce()
            .then(nonce => {
                return this.api.axios.post('/auth/disableTotp', {}, {
                    nonce: nonce,
                    signRequest: self.sign.bind(this)
                });
            }).then(() => {
                self.is_totp_enabled = false;
            })
    }

    sign(message) {
        if (!_.isString(message)) {
            throw new TypeError('message must be a String.');
        }

        let keypair = StellarSdk.Keypair.fromSecret(this.seed)
        return crypto.signMessage(message, keypair._secretKey)
    }
}

module.exports = Wallet;
