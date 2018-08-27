'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Argus = exports.ARGUS_AUTH_TYPES = exports.ARGUS_SECURITY_TYPES = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _async = require('async');

var _async2 = _interopRequireDefault(_async);

var _ResponseBody = require('./ResponseBody');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var VERSION = '0.1.6';
var SECURITY_TYPES = {
  JWT: Symbol('JWT'),
  JWT_WITH_PAYLOAD_DECRYPTION: Symbol('JWT_WITH_PAYLOAD_DECRYPTION')
};
var AUTH_TYPES = {
  BASIC: Symbol('BASIC')
};
var AUTH_SPLITERS = ['Basic ', 'Bearer '];
var DEFAULT_CONFIG = {
  USERNAME_PROP: 'username',
  PASSWORD_PROP: 'password',
  PASSWORD_SALT: 'Im Batman!',
  JWT_SECRET: 'Im Batman!',
  ENCRYPTION_SECRET: '0000000000000000',
  ENCRYPTION_ALGORITHM: 'aes-256-cbc',
  BUFFER_FORMAT: 'hex',
  IV: '0000000000000000',
  IV_LENGTH: 16,
  ENCODING: 'base64',
  KEY_LENGTH: 16,
  KEY_FORMAT: 'base64'
};

exports.ARGUS_SECURITY_TYPES = SECURITY_TYPES;
exports.ARGUS_AUTH_TYPES = AUTH_TYPES;

var Argus = exports.Argus = function () {
  function Argus() {
    var config = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, Argus);

    this.CONFIG = Object.assign({}, DEFAULT_CONFIG, config);

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

    this.decodeAuth = this.decodeAuth.bind(this);
    this._extractAuthToken = this._extractAuthToken.bind(this);
    this._decodeAuthToken = this._decodeAuthToken.bind(this);
    this._decodeBasicAuthToken = this._decodeBasicAuthToken.bind(this);
  }

  _createClass(Argus, [{
    key: 'generateKey',
    value: function generateKey() {
      var length = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 16;
      var format = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var CONFIG = this.CONFIG;

      var thisLength = length || CONFIG.KEY_LENGTH;
      var thisFormat = length || CONFIG.KEY_FORMAT;
      return _crypto2.default.randomBytes(thisLength).toString(thisFormat);
    }
  }, {
    key: 'encryptPassword',
    value: function encryptPassword() {
      var password = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var salt = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var CONFIG = this.CONFIG,
          hmacSha256 = this.hmacSha256;

      var thisSalt = salt || CONFIG.DEFAULT_PASSWORD_SALT;
      return hmacSha256(password, thisSalt);
    }
  }, {
    key: 'verifyPassword',
    value: function verifyPassword() {
      var password = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var hash = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var salt = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : '';
      var CONFIG = this.CONFIG,
          encryptPassword = this.encryptPassword;

      var thisSalt = salt || CONFIG.PASSWORD_SALT;
      var passwordHash = encryptPassword(password, thisSalt);
      return passwordHash === hash;
    }
  }, {
    key: 'createJWT',
    value: function createJWT() {
      var claims = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
      var secret = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var CONFIG = this.CONFIG,
          encode = this.encode,
          hmacSha256 = this.hmacSha256;

      var thisSecret = secret || CONFIG.JWT_SECRET;
      var encoding = CONFIG.ENCODING;
      var header = {
        alg: 'HS256',
        typ: 'JWT'
      };

      var jwtHeader = encode(JSON.stringify(header), encoding);
      var jwtClaims = encode(JSON.stringify(claims), encoding);
      var jwtSignature = hmacSha256(jwtHeader + jwtClaims, thisSecret);

      return [jwtHeader, jwtClaims, jwtSignature].join('.');
    }
  }, {
    key: 'decodeJWT',
    value: function decodeJWT(authToken) {
      var CONFIG = this.CONFIG,
          decode = this.decode;

      var encoding = CONFIG.ENCODING;
      var error = void 0;

      if (!(authToken && authToken.length)) {
        error = new _ResponseBody.ResponseBody(401, 'Missing/Invalid Authorization');
        return error;
      }

      var jwtArray = authToken && authToken.split('.');

      if (jwtArray.length !== 3) {
        error = new _ResponseBody.ResponseBody(400, 'Invalid Authorization Token');
        return error;
      }

      var header = decode(jwtArray[0], encoding);
      var claims = decode(jwtArray[1], encoding);
      var signature = jwtArray[2];

      try {
        header = JSON.parse(header);
        claims = JSON.parse(claims);
      } catch (e) {
        error = new _ResponseBody.ResponseBody(400, 'Invalid Authorization Token');
        return error;
      }

      if (header.constructor.name !== 'Object' || claims.constructor.name !== 'Object') {
        error = new _ResponseBody.ResponseBody(400, 'Invalid JWT Header/Claims');
        return error;
      }

      return { header: header, claims: claims, signature: signature };
    }
  }, {
    key: 'verifyJWT',
    value: function verifyJWT(decryptedJWT) {
      var secret = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var CONFIG = this.CONFIG,
          encode = this.encode,
          hmacSha256 = this.hmacSha256;

      var thisSecret = secret || CONFIG.JWT_SECRET;
      var encoding = CONFIG.ENCODING;
      var header = JSON.stringify(decryptedJWT.header);
      var claims = JSON.stringify(decryptedJWT.claims);
      var signature = decryptedJWT.signature;

      var hash = encode(header + claims, encoding);
      hash = hmacSha256(hash, thisSecret);
      return hash === signature;
    }
  }, {
    key: 'encryptPayload',
    value: function encryptPayload() {
      var plainText = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var secretKey = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var CONFIG = this.CONFIG,
          cipher = this.cipher;

      var thisSecretKey = secretKey || CONFIG.ENCRYPTION_SECRET;
      var algorithm = CONFIG.ENCRYPTION_ALGORITHM;
      var key = thisSecretKey;
      var iv = _crypto2.default.randomBytes(CONFIG.IV_LENGTH);
      var bufferFormat = CONFIG.BUFFER_FORMAT;
      var encrypted = cipher(algorithm, plainText, key, iv, bufferFormat);
      var payload = iv.toString(bufferFormat) + ':' + encrypted;
      return payload;
    }
  }, {
    key: 'decryptPayload',
    value: function decryptPayload() {
      var payload = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var secretKey = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var CONFIG = this.CONFIG,
          decipher = this.decipher;

      var thisSecretKey = secretKey || CONFIG.ENCRYPTION_SECRET;
      if (!payload) {
        return;
      }

      var payloadParts = payload.split(':');
      if (payloadParts.length !== 2) {
        return 'Invalid Payload';
      }

      try {
        var key = thisSecretKey;
        var algorithm = CONFIG.ENCRYPTION_ALGORITHM;
        var iv = payloadParts[0];
        var encryptedText = payloadParts[1];
        var bufferFormat = CONFIG.BUFFER_FORMAT;
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
      var decodeJWT = _this.decodeJWT,
          _extractAuthToken = _this._extractAuthToken;
      var headers = request.headers,
          query = request.query;
      var authorization = headers.authorization;
      var token = query.token;

      var authToken = _extractAuthToken(authorization) || token;
      request.token = authToken;

      var applySwitch = (_applySwitch = {}, _defineProperty(_applySwitch, SECURITY_TYPES.JWT, function () {
        var jwt = decodeJWT(authToken);
        var claims = jwt.claims;


        request.jwt = jwt;
        request.user = claims;
      }), _defineProperty(_applySwitch, SECURITY_TYPES.JWT_WITH_PAYLOAD_DECRYPTION, function () {
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
      var CONFIG = this.CONFIG;

      var thisSalt = salt || CONFIG.PASSWORD_SALT;
      var hmac = _crypto2.default.createHmac('sha256', thisSalt);
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
      var CONFIG = this.CONFIG;

      var thisKey = key || CONFIG.ENCRYPTION_SECRET;
      var thisIV = iv || CONFIG.IV;
      var bufferFormat = CONFIG.BUFFER_FORMAT;

      var keyBuffer = Buffer.from(thisKey);
      var ivBuffer = Buffer.from(thisIV, bufferFormat);
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
      var CONFIG = this.CONFIG;

      var thisKey = key || CONFIG.ENCRYPTION_SECRET;
      var thisIV = iv || CONFIG.IV;
      var bufferFormat = CONFIG.BUFFER_FORMAT;

      var keyBuffer = Buffer.from(thisKey);
      var ivBuffer = Buffer.from(thisIV, bufferFormat);
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
      var encoding = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var CONFIG = this.CONFIG;

      var thisEncoding = encoding || CONFIG.ENCODING;
      return Buffer.from(plainText).toString(thisEncoding);
    }
  }, {
    key: 'decode',
    value: function decode() {
      var cipherText = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var encoding = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var CONFIG = this.CONFIG;

      var thisEncoding = encoding || CONFIG.ENCODING;
      return Buffer.from(cipherText, thisEncoding).toString('utf8');
    }
  }, {
    key: 'decodeAuth',
    value: function decodeAuth(authType, auth) {
      var _extractAuthToken = this._extractAuthToken,
          _decodeAuthToken = this._decodeAuthToken;

      var authTypeValues = Object.keys(AUTH_TYPES).map(function (type) {
        return AUTH_TYPES[type];
      });
      var error = void 0;

      if (authTypeValues.indexOf(authType) === -1) {
        error = new _ResponseBody.ResponseBody(400, "Invalid 'authType' for Decoding");
        return error;
      }

      if (!auth) {
        error = new _ResponseBody.ResponseBody(400, 'Auth Not Found');
        return error;
      }

      var token = _extractAuthToken(auth);
      if (!token) {
        error = new _ResponseBody.ResponseBody(400, 'Invalid Auth');
        return error;
      }

      var credentials = _decodeAuthToken(authType, token);
      if (!credentials) {
        error = new _ResponseBody.ResponseBody(400, 'Invalid Auth Credentials');
        return error;
      }

      return credentials;
    }
  }, {
    key: '_extractAuthToken',
    value: function _extractAuthToken(auth) {
      var parts = void 0,
          token = void 0;

      AUTH_SPLITERS.forEach(function (spliter) {
        if (token) {
          return;
        }
        parts = auth.split(spliter);
        if (parts[0] === '' && parts[1]) {
          token = parts[1];
        }
      });
      return token;
    }
  }, {
    key: '_decodeAuthToken',
    value: function _decodeAuthToken(authType) {
      var token = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
      var _decodeBasicAuthToken = this._decodeBasicAuthToken;

      var credentials = void 0;
      if (authType === AUTH_TYPES.BASIC) {
        credentials = _decodeBasicAuthToken(token);
      }
      return credentials;
    }
  }, {
    key: '_decodeBasicAuthToken',
    value: function _decodeBasicAuthToken() {
      var _credentials;

      var token = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var CONFIG = this.CONFIG;
      var USERNAME_PROP = CONFIG.USERNAME_PROP,
          PASSWORD_PROP = CONFIG.PASSWORD_PROP;

      var error = void 0,
          credentialParts = void 0,
          credentials = void 0;
      var encoding = 'base64';

      credentialParts = this.decode(token, encoding);
      credentialParts = credentialParts.split(':');
      if (credentials.length !== 2) {
        error = new _ResponseBody.ResponseBody(400, 'Invalid Auth Token');
      }

      credentials = (_credentials = {}, _defineProperty(_credentials, USERNAME_PROP, credentialParts[0]), _defineProperty(_credentials, PASSWORD_PROP, credentialParts[1]), _credentials);

      return error || credentials;
    }
  }], [{
    key: 'SECURITY_TYPES',
    get: function get() {
      return SECURITY_TYPES;
    }
  }, {
    key: 'VERSION',
    get: function get() {
      return VERSION;
    }
  }]);

  return Argus;
}();