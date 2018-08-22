'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ExpressRouteHelper = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Argus = require('./Argus');

var _ResponseBody = require('./ResponseBody');

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var argus = new _Argus.Argus();

var ExpressRouteHelper = exports.ExpressRouteHelper = function () {
  function ExpressRouteHelper(_ref) {
    var AuthModel = _ref.AuthModel,
        SUPERADMIN_ROLE = _ref.SUPERADMIN_ROLE;

    _classCallCheck(this, ExpressRouteHelper);

    this.AuthModel = AuthModel;
    this.SUPERADMIN_ROLE = SUPERADMIN_ROLE;

    // Method Hard-binding
    this.applyJWT = this.applyJWT.bind(this);
    this.applyJWTandEncryption = this.applyJWTandEncryption.bind(this);
    this.validateSecurity = this.validateSecurity.bind(this);
    this.manageSelfAccess = this.manageSelfAccess.bind(this);
    this.manageSuperadminAccess = this.manageSuperadminAccess.bind(this);
    this.responseBody = this.responseBody.bind(this);
    this.sendEncryptedResponse = this.sendEncryptedResponse.bind(this);
  }

  _createClass(ExpressRouteHelper, [{
    key: 'applyJWT',
    value: function applyJWT(request, response, next) {
      argus.applySecurity(_Argus.ARGUS_SECURITY_TYPES.JWT, request, response, next);
    }
  }, {
    key: 'applyJWTandEncryption',
    value: function applyJWTandEncryption(request, response, next) {
      argus.applySecurity(_Argus.ARGUS_SECURITY_TYPES.JWT_WITH_PAYLOAD_ENCRYPTION, request, response, next);
    }
  }, {
    key: 'validateSecurity',
    value: function validateSecurity(request, response, next) {
      var AuthModel = this.AuthModel;
      var getSecretKey = AuthModel.getSecretKey;

      var options = { getSecretKey: getSecretKey };
      argus.validateSecurity(options, request, response, next);
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
      var SUPERADMIN_ROLE = this.SUPERADMIN_ROLE;
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
      var responseBody = response.body;
      var encryptionKey = response._encryptionKey || request._encryptionKey;
      var token = response.token || request.token;

      var payload = aegis.encryptPayload(responseBody, token);
      var body = { token: token, payload: payload };
      response.status(200).json(body);
    }
  }]);

  return ExpressRouteHelper;
}();