'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Argus = exports.ARGUS_SECURITY_TYPES = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _async = require('async');

var _async2 = _interopRequireDefault(_async);

var _ResponseBody = require('./ResponseBody');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var VERSION = '0.1.0';
var DEFAULT_PASSWORD_SALT = 'Im Batman!';
var IV_LENGTH = 16;
var SECURITY_TYPES = {
  JWT: Symbol('JWT'),
  JWT_WITH_PAYLOAD_ENCRYPTION: Symbol('JWT_WITH_PAYLOAD_ENCRYPTION')
};

exports.ARGUS_SECURITY_TYPES = SECURITY_TYPES;

var Argus = exports.Argus = function () {
  function Argus() {
    var config = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, Argus);

    // Method Hard-Binding
    this.generateKey = this.generateKey.bind(this);
    this.encryptPassword = this.encryptPassword.bind(this);
    this.verifyPassword = this.verifyPassword.bind(this);

    this.createJWT = this.createJWT.bind(this);
    this.decodeJWT = this.decodeJWT.bind(this);
    this.verifyJWT = this.verifyJWT.bind(this);

    this.encryptPayload = this.encryptPayload.bind(this);
    this.decryptPayload = this.decryptPayload.bind(this);

    this.applySecurity = this.applySecurity.bind(this);
    this.validateSecurity = this.validateSecurity.bind(this);

    this.hmacSha256 = this.hmacSha256.bind(this);

    this.cipher = this.cipher.bind(this);
    this.decipher = this.decipher.bind(this);

    this.encode = this.encode.bind(this);
    this.decode = this.decode.bind(this);
  }

  _createClass(Argus, [{
    key: 'generateKey',
    value: function generateKey() {
      var length = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 16;
      var format = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'base64';

      return _crypto2.default.randomBytes(length).toString(format);
    }
  }, {
    key: 'encryptPassword',
    value: function encryptPassword(password, salt) {
      var hmacSha256 = this.hmacSha256;

      return hmacSha256(password, salt || DEFAULT_PASSWORD_SALT);
    }
  }, {
    key: 'verifyPassword',
    value: function verifyPassword(password, hash, salt) {
      var encryptPassword = this.encryptPassword;

      var passwordHash = encryptPassword(password, salt);
      return passwordHash === hash;
    }
  }, {
    key: 'createJWT',
    value: function createJWT(claims, secret) {
      var encode = this.encode,
          hmacSha256 = this.hmacSha256;

      var encoding = 'base64';
      var header = {
        alg: 'HS256',
        typ: 'JWT'
      };

      var jwtHeader = encode(JSON.stringify(header), encoding);
      var jwtClaims = encode(JSON.stringify(claims), encoding);
      var jwtSignature = hmacSha256(jwtHeader + jwtClaims, secret);

      return [jwtHeader, jwtClaims, jwtSignature].join('.');
    }
  }, {
    key: 'decodeJWT',
    value: function decodeJWT(authToken) {
      var decode = this.decode;

      var encoding = 'base64';
      var error = void 0,
          responseBody = void 0;

      if (!(authToken && authToken.length)) {
        error = 'Missing/Invalid Authorization';
        responseBody = new _ResponseBody.ResponseBody(401, error);
        return responseBody;
      }

      var jwtArray = authToken && authToken.split('.');

      if (jwtArray.length !== 3) {
        error = 'Invalid Authorization Token';
        responseBody = new _ResponseBody.ResponseBody(400, error);
        return responseBody;
      }

      var header = decode(jwtArray[0], encoding);
      var claims = decode(jwtArray[1], encoding);
      var signature = jwtArray[2];

      try {
        header = JSON.parse(header);
        claims = JSON.parse(claims);
      } catch (e) {
        error = 'Invalid Authorization Token';
        responseBody = new _ResponseBody.ResponseBody(400, error);
        return responseBody;
      }

      if (header.constructor.name !== 'Object' || claims.constructor.name !== 'Object') {
        error = 'Invalid JWT Header/Claims';
        responseBody = new _ResponseBody.ResponseBody(400, error);
        return responseBody;
      }

      return { header: header, claims: claims, signature: signature };
    }
  }, {
    key: 'verifyJWT',
    value: function verifyJWT(decryptedJWT, secret) {
      var encode = this.encode,
          hmacSha256 = this.hmacSha256;

      var encoding = 'base64';
      var header = JSON.stringify(decryptedJWT.header);
      var claims = JSON.stringify(decryptedJWT.claims);
      var signature = decryptedJWT.signature;

      var hash = encode(header + claims, encoding);
      hash = hmacSha256(hash, secret);
      return hash === signature;
    }
  }, {
    key: 'encryptPayload',
    value: function encryptPayload() {
      var plainText = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var secretKey = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var cipher = this.cipher;

      var algorithm = 'aes-256-cbc';
      var key = secretKey.substring(16, 48);
      var iv = _crypto2.default.randomBytes(IV_LENGTH);
      var bufferFormat = 'hex';
      var encrypted = cipher(algorithm, plainText, key, iv, bufferFormat);
      var payload = iv.toString(bufferFormat) + ':' + encrypted;
      return payload;
    }
  }, {
    key: 'decryptPayload',
    value: function decryptPayload() {
      var payload = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var secretKey = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var decipher = this.decipher;

      if (!payload) {
        return;
      }

      var payloadParts = payload.split(':');
      if (payloadParts.length !== 2) {
        return 'Invalid Payload';
      }

      try {
        var key = secretKey.substring(16, 48);
        var algorithm = 'aes-256-cbc';
        var iv = payloadParts[0];
        var encryptedText = payloadParts[1];
        var bufferFormat = 'hex';
        var decrypted = decipher(algorithm, encryptedText, key, iv, bufferFormat);
        var _body = JSON.parse(decrypted);
        return _body;
      } catch (e) {
        return 'Failed Parsing Payload';
      }
    }
  }, {
    key: 'applySecurity',
    value: function applySecurity(securityType, request, response, callback) {
      var _applySwitch;

      var _this = this;
      var decodeJWT = _this.decodeJWT;
      var headers = request.headers,
          query = request.query;
      var authorization = headers.authorization;
      var token = query.token;

      var authToken = authorization && authorization.split('Bearer ')[1] || token;
      request.token = authToken;

      var applySwitch = (_applySwitch = {}, _defineProperty(_applySwitch, SECURITY_TYPES.JWT, function () {
        var jwt = decodeJWT(authToken);
        var claims = jwt.claims;


        request.jwt = jwt;
        request.user = claims;
      }), _defineProperty(_applySwitch, SECURITY_TYPES.JWT_WITH_PAYLOAD_ENCRYPTION, function () {
        var jwt = decodeJWT(authToken);
        var claims = jwt.claims;


        request.jwt = jwt;
        request.user = claims;

        request._decryptPayload = true;
      }), _applySwitch);
      var thisSwitch = applySwitch[securityType];

      if (thisSwitch) {
        thisSwitch(request);
      }
      process.nextTick(callback);
    }
  }, {
    key: 'validateSecurity',
    value: function validateSecurity() {
      var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
      var request = arguments[1];
      var response = arguments[2];
      var callback = arguments[3];

      var _this = this;
      var verifyJWT = _this.verifyJWT,
          decryptPayload = _this.decryptPayload;
      var jwt = request.jwt,
          _request$user = request.user,
          user = _request$user === undefined ? {} : _request$user,
          body = request.body,
          _decryptPayload = request._decryptPayload;

      var err = void 0,
          responseBody = void 0;

      _async2.default.waterfall([
      // Validate JWT and Body
      function (next) {
        if (jwt instanceof _ResponseBody.ResponseBody) {
          return process.nextTick(function () {
            return next(jwt);
          });
        }

        if (body instanceof Error) {
          err = body.toString();
          responseBody = new _ResponseBody.ResponseBody(500, err, body);
          return process.nextTick(function () {
            return next(responseBody);
          });
        }
      },

      // Get User's Secret Key
      function (next) {
        var id = user.id;
        var getSecretKey = options.getSecretKey;


        if (!(getSecretKey instanceof Function)) {
          err = 'Error Getting User Secret Key';
          responseBody = new _ResponseBody.ResponseBody(500, err);
          return process.nextTick(function () {
            return next(err);
          });
        }

        getSecretKey(id, function (error, key) {
          if (error) {
            err = error.toString();
            responseBody = new _ResponseBody.ResponseBody(500, err, error);
            return next(responseBody);
          }

          next(null, key);
        });
      },

      // Handle JWT
      function (key, next) {
        var jwtValid = verifyJWT(jwt, key);

        if (!jwtValid) {
          err = 'JWT Tampered, Signature does not match';
          responseBody = new _ResponseBody.ResponseBody(400, err);
          return process.nextTick(function () {
            return next(responseBody);
          });
        }

        request.secretKey = key;
        return process.nextTick(next);
      },

      // Handle Payload Decryption Key
      function (next) {
        if (_decryptPayload !== true) {
          return process.nextTick(next);
        }

        var getEncryptionKey = options.getEncryptionKey;
        var _request$token = request.token,
            token = _request$token === undefined ? '' : _request$token;

        var key = token && token.substring(16, 48);
        request._encryptionKey = key;

        if (getEncryptionKey instanceof Function) {
          return getEncryptionKey(function (error, key) {
            if (error) {
              err = 'Error Fetching Encryption Key';
              responseBody = new _ResponseBody.ResponseBody(500, err);
              return next(responseBody);
            }

            request._encryptionKey = key;
            next();
          });
        }

        process.nextTick(next);
      },

      // Handle Payload Decryption
      function (next) {
        if (_decryptPayload !== true) {
          return process.nextTick(next);
        }

        var body = request.body,
            _request$_encryptionK = request._encryptionKey,
            _encryptionKey = _request$_encryptionK === undefined ? '' : _request$_encryptionK;

        var _body$payload = body.payload,
            payload = _body$payload === undefined ? '' : _body$payload;

        var _body = decryptPayload(payload, _encryptionKey);

        if (typeof _body === 'string') {
          err = _body;
          responseBody = new _ResponseBody.ResponseBody(400, err);
          return process.nextTick(function () {
            return next(err);
          });
        } else {
          request.body = _body && Object.assign({}, body, _body) || {};
          return process.nextTick(function () {
            return next();
          });
        }
      }], function (error) {
        if (error) {
          response.body = error;
        }
        callback();
      });
    }
  }, {
    key: 'hmacSha256',
    value: function hmacSha256() {
      var plainText = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var salt = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';

      var hmac = _crypto2.default.createHmac('sha256', salt);
      var hash = hmac.update(plainText, 'utf8').digest('base64');
      return hash;
    }
  }, {
    key: 'cipher',
    value: function cipher() {
      var algorithm = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var plainText = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var key = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : '';
      var iv = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : '';
      var bufferFormat = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : 'hex';

      var keyBuffer = Buffer.from(key);
      var ivBuffer = Buffer.from(iv, bufferFormat);
      var cipher = _crypto2.default.createCipheriv(algorithm, keyBuffer, ivBuffer);

      var encrypted = cipher.update(plainText);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      encrypted = encrypted.toString(bufferFormat);
      return encrypted;
    }
  }, {
    key: 'decipher',
    value: function decipher() {
      var algorithm = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var cipherText = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var key = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : '';
      var iv = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : '';
      var bufferFormat = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : 'hex';

      var keyBuffer = Buffer.from(key);
      var ivBuffer = Buffer.from(iv, bufferFormat);
      var cipherBuffer = Buffer.from(cipherText, bufferFormat);
      var decipher = _crypto2.default.createDecipheriv(algorithm, keyBuffer, ivBuffer);

      var decrypted = decipher.update(cipherBuffer);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      decrypted = decrypted.toString();
      return decrypted;
    }
  }, {
    key: 'encode',
    value: function encode() {
      var plainText = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var encoding = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'base64';

      return Buffer.from(plainText).toString(encoding);
    }
  }, {
    key: 'decode',
    value: function decode() {
      var cipherText = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var encoding = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'base64';

      return Buffer.from(cipherText, encoding).toString('utf8');
    }
  }], [{
    key: 'SECURITY_TYPES',
    get: function get() {
      return SECURITY_TYPES;
    }
  }, {
    key: '__version',
    get: function get() {
      return VERSION;
    }
  }]);

  return Argus;
}();