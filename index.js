'use strict';

var _ = require('lodash');
var path = require('path');
var fs = require('fs');
var crypto = require('crypto');
var moment = require('moment');

var iconv = require('iconv-lite');
var request = require('request');

var Promise = require('bluebird');
var NodeRSA = require('node-rsa');

var ALIPAY_GATEWAY = 'https://openapi.alipay.com/gateway.do';

function createPromiseCallback() {
    var cb;
    var promise = new Promise(function (resolve, reject) {
        cb = function (err, data) {
            if (err) return reject(err);
            return resolve(data);
        };
    });
    cb.promise = promise;
    return cb;
};

// 除去数组中的空值和签名参数
var paramsFilter = function (params) {
    var result = {};
    if (!params) {
        return result;
    }
    for (var k in params) {
        if (!params[k] || params[k] === '' || k === 'sign') {
            continue;
        }
        result[k] = params[k];
    }
    return result;
};

// 将所有参数按照“参数=参数值”的模式用“&”字符拼接成字符串
var toQueryString = function (params) {
    var result = '';
    var sortKeys = Object.keys(params).sort();
    for (var i in sortKeys) {
        result += sortKeys[i] + '=' + params[sortKeys[i]] + '&';
    }
    if (result.length > 0) {
        return result.slice(0, -1);
    } else {
        return result;
    }
};

var Alipay = function (options) {
    this._options = options;
    return this;
};

Alipay.prototype._encryptedParams = function (params) {
    var qs = toQueryString(paramsFilter(params));
    var key = new NodeRSA(fs.readFileSync(this._options.alipay_public_key), {
        encryptionScheme: 'pkcs1'
    });
    var encrypted = key.encrypt(qs, 'base64');
    return encrypted;
};

Alipay.prototype._decryptedParams = function (toDecrypt) {
    var key = new NodeRSA(fs.readFileSync(this._options.private_key), {
        encryptionScheme: 'pkcs1'
    });
    var decrypted = key.decrypt(toDecrypt, 'utf8');
    return decrypted;
};

Alipay.prototype._generateSign = function (params) {
    var qs = toQueryString(paramsFilter(params));
    if (params.sign_type === 'RSA') {
        return crypto.createSign('RSA-SHA1').update(new Buffer(qs, 'utf8')).sign(fs.readFileSync(this._options.private_key), 'base64');
    } else if (params.sign_type === 'RSA2') {
        return crypto.createSign('RSA-SHA256').update(new Buffer(qs, 'utf8')).sign(fs.readFileSync(this._options.private_key), 'base64');
    } else {
        return undefined;
    }
};

Alipay.prototype._verifySign = function (params, signature) {
    var qs = toQueryString(paramsFilter(params));
    if (params.sign_type === 'RSA') {
        return crypto.createVerify('RSA-SHA1').update(new Buffer(qs, 'utf8')).verify(fs.readFileSync(this._options.alipay_public_key), signature, 'base64');
    } else if (params.sign_type === 'RSA2') {
        return crypto.createVerify('RSA-SHA256').update(new Buffer(qs, 'utf8')).verify(fs.readFileSync(this._options.alipay_public_key), signature, 'base64');
    } else {
        return false;
    }
};

Alipay.prototype.request = function (params, cb) {
    cb = cb || createPromiseCallback();

    var self = this;

    params = _.extend({
        app_id: self._options.app_id,
        format: 'JSON',
        charset: 'gb2312',
        sign_type: self._options.sign_type || 'RSA',
        timestamp: moment().format('YYYY-MM-DD HH:mm:ss'),
        version: '1.0'
    }, params);

    params.sign = self._generateSign(params);

    request({
        url: ALIPAY_GATEWAY,
        method: 'POST',
        encoding: null,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded; charset=gb2312'
        },
        form: params
    }, function (err, response, body) {
        if (err) {
            cb(err)
        } else {
            var data = JSON.parse(iconv.decode(body, 'gb2312'));
            if (data.error_response) {
                cb(new Error(data.error_response.msg));
            } else {
                cb(null, data);
            }
        }
    });

    return cb.promise;
};

module.exports = Alipay;