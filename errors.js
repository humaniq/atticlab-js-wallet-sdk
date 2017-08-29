/* * Copyright 2017 Atticlab LLC.
 * Licensed under the Apache License, Version 2.0
 * See the LICENSE or LICENSE_UA file at the root of this repository
 * Contact us at http://atticlab.net
 */
function createError(errorName) {
    var err = function (message, descr) {
        this.name = errorName;
        this.message = (message || "");
        this.description = (descr || "");
    };

    err.prototype = Error.prototype;
    return err;
};


module.exports = {
    UnknownError: createError('UnknownError'),
    ConnectionError: createError('ConnectionError'),
    ApiError: createError('ApiError'),
    getProtocolError: function (code, msg) {
        if (typeof msg == 'undefined') {
            msg = '';
        }

        switch (code) {
            case'ERR_SERVICE':
            case'ERR_NOT_FOUND':
            case'ERR_ALREADY_EXISTS':
            case'ERR_BAD_PARAM':
            case'ERR_EMPTY_PARAM':
            case'ERR_NOT_ALLOWED':
            case'ERR_TOTP_DISABLED':
            case'ERR_BAD_SIGN':
            case'ERR_SMS_LIMIT':
            case'ERR_NO_PHONE':
            case'ERR_TFA_TOTP':
            case'ERR_TFA_SMS':
            case'ERR_MAINTENANCE':
                return new this.ApiError(code, msg);

            default:
                return new this.UnknownError(code, 'Unknown error');
        }
    }
}