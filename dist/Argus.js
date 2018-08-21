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
    value: function decodeJWT(request) {
      var decode = this.decode;

      var encoding = 'base64';
      var headers = request.headers;
      var authorization = headers.authorization;

      var authToken = authorization && authorization.split('Bearer ')[1];
      request.token = authToken;

      if (!(authToken && authToken.length)) {
        return new Error('Missing/Invalid Authorization in Request Header');
      }

      var jwtArray = authToken && authToken.split('.');

      if (jwtArray.length !== 3) {
        return new Error('Invalid JWT Token');
      }

      var header = decode(jwtArray[0], encoding);
      var claims = decode(jwtArray[1], encoding);
      var signature = jwtArray[2];

      try {
        header = JSON.parse(header);
        claims = JSON.parse(claims);
      } catch (e) {
        return new Error('Invalid JWT Token');
      }

      if (header.constructor.name !== 'Object' || claims.constructor.name !== 'Object') {
        return new Error('Invalid JWT Header/Claims');
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

      var applySwitch = (_applySwitch = {}, _defineProperty(_applySwitch, SECURITY_TYPES.JWT, function () {
        var jwt = decodeJWT(request);
        var claims = jwt.claims;


        request.jwt = jwt;
        request.user = claims;
      }), _defineProperty(_applySwitch, SECURITY_TYPES.JWT_WITH_PAYLOAD_ENCRYPTION, function () {
        var jwt = decodeJWT(request);
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


      if (jwt instanceof Error) {
        return process.nextTick(function () {
          return callback(jwt);
        });
      }

      if (body instanceof Error) {
        return process.nextTick(function () {
          return callback(body);
        });
      }

      _async2.default.waterfall([
      // Get User's Secret Key
      function (next) {
        var id = user.id;
        var getSecretKey = options.getSecretKey;


        if (!(getSecretKey instanceof Function)) {
          var error = new Error('Error Getting User Secret Key');
          return process.nextTick(function () {
            return next(error);
          });
        }

        getSecretKey(id, next);
      },

      // Handle JWT
      function (key, next) {
        var jwtValid = verifyJWT(jwt, key);

        if (!jwtValid) {
          var error = new Error('Unauthorized Access - JWT Signature does not match');
          return process.nextTick(function () {
            return next(error);
          });
        }

        request.secretKey = key;
        return process.nextTick(next);
      },

      // Handle Payload Decryption
      function (next) {
        if (_decryptPayload !== true) {
          return process.nextTick(next);
        }

        var body = request.body,
            _request$token = request.token,
            token = _request$token === undefined ? '' : _request$token;
        var _body$payload = body.payload,
            payload = _body$payload === undefined ? '' : _body$payload;

        var _body = decryptPayload(payload, token);
        if (typeof _body === 'string') {
          var error = new Error(_body);
          return process.nextTick(function () {
            return next(error);
          });
        } else {
          request.body = _body && Object.assign({}, body, _body) || {};
          return process.nextTick(function () {
            return next();
          });
        }
      }], callback);
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