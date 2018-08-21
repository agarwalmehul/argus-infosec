'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _Argus = require('./Argus');

Object.keys(_Argus).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _Argus[key];
    }
  });
});