'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ExpressRouteHelper = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Argus = require('./Argus');

var _ResponseBody = require('./ResponseBody');

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var DEFAULT_CONFIG = {
  SUPERADMIN_ROLE: 'SUPERADMIN',
  USERNAME_PROP: 'username',
  PASSWORD_PROP: 'password'
};

var ExpressRouteHelper = exports.ExpressRouteHelper = function () {
  function ExpressRouteHelper(AuthModel) {
    var CONFIG = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    _classCallCheck(this, ExpressRouteHelper);

    this.AuthModel = AuthModel;
    this.CONFIG = Object.assign({}, DEFAULT_CONFIG, CONFIG);
    this.argus = new _Argus.Argus(this.CONFIG);

    // Method Hard-binding
    this.applyJWT = this.applyJWT.bind(this);
    this.applyJWTandDecryptPayload = this.applyJWTandDecryptPayload.bind(this);
    this.validateSecurity = this.validateSecurity.bind(this);

    this.manageSelfAccess = this.manageSelfAccess.bind(this);
    this.manageSuperadminAccess = this.manageSuperadminAccess.bind(this);

    this.sendResponse = this.sendResponse.bind(this);
    this.sendEncryptedResponse = this.sendEncryptedResponse.bind(this);

    this.decodeBasicAuth = this.decodeBasicAuth.bind(this);
  }

  _createClass(ExpressRouteHelper, [{
    key: 'applyJWT',
    value: function applyJWT(request, response, next) {
      this.argus.applySecurity(_Argus.ARGUS_SECURITY_TYPES.JWT, request, response, next);
    }
  }, {
    key: 'applyJWTandDecryptPayload',
    value: function applyJWTandDecryptPayload(request, response, next) {
      this.argus.applySecurity(_Argus.ARGUS_SECURITY_TYPES.JWT_WITH_PAYLOAD_DECRYPTION, request, response, next);
    }
  }, {
    key: 'validateSecurity',
    value: function validateSecurity(request, response, next) {
      var AuthModel = this.AuthModel;
      var getSecretKey = AuthModel.getSecretKey;

      var options = { getSecretKey: getSecretKey };
      this.argus.validateSecurity(options, request, response, next);
    }
  }, {
    key: 'manageSelfAccess',
    value: function manageSelfAccess(request, response, next) {
      var _request$user = request.user,
          user = _request$user === undefined ? {} : _request$user,
          params = request.params,
          body = request.body;

      var id = params.id || body.id;

      if (id !== user.id) {
        var error = new _ResponseBody.ResponseBody(403, 'Forbidden');
        response.body = error;
      }

      process.nextTick(next);
    }
  }, {
    key: 'manageSuperadminAccess',
    value: function manageSuperadminAccess(request, response, next) {
      var CONFIG = this.CONFIG;
      var SUPERADMIN_ROLE = CONFIG.SUPERADMIN_ROLE;
      var _request$user2 = request.user,
          user = _request$user2 === undefined ? {} : _request$user2;
      var _user$role = user.role,
          role = _user$role === undefined ? '' : _user$role,
          _user$roles = user.roles,
          roles = _user$roles === undefined ? [] : _user$roles;

      var isSuperAdmin = role === SUPERADMIN_ROLE || roles.indexOf(SUPERADMIN_ROLE) > -1;

      if (!isSuperAdmin) {
        var error = new _ResponseBody.ResponseBody(403, 'Forbidden');
        response.body = error;
      }

      process.nextTick(next);
    }
  }, {
    key: 'sendResponse',
    value: function sendResponse(request, response, next) {
      var body = response.body;

      response.status(body.statusCode).json(body);
    }
  }, {
    key: 'sendEncryptedResponse',
    value: function sendEncryptedResponse(request, response, next) {
      var sendResponse = this.sendResponse;
      var _response$body = response.body,
          body = _response$body === undefined ? {} : _response$body;

      var responseBody = JSON.stringify(body);
      var encryptionKey = response._encryptionKey || request._encryptionKey;
      var token = response.token || request.token;

      if (!token) {
        return sendResponse(request, response, next);
      }

      var payload = this.argus.encryptPayload(responseBody, encryptionKey);
      var _body = { token: token, payload: payload };
      response.status(200).json(_body);
    }
  }, {
    key: 'decodeBasicAuth',
    value: function decodeBasicAuth(request, response, next) {
      var headers = request.headers,
          body = request.body;
      var authorization = headers.authorization;

      var authType = _Argus.ARGUS_AUTH_TYPES.BASIC;
      var credentials = this.argus.decodeAuth(authType, authorization);
      request.body = credentials;
      process.nextTick(next);
    }
  }]);

  return ExpressRouteHelper;
}();