import crypto from 'crypto'
import async from 'async'
import { ResponseBody } from './ResponseBody'

const VERSION = '0.1.10'
const SECURITY_TYPES = {
  JWT: Symbol('JWT'),
  JWT_WITH_PAYLOAD_DECRYPTION: Symbol('JWT_WITH_PAYLOAD_DECRYPTION')
}
const AUTH_TYPES = {
  BASIC: Symbol('BASIC')
}
const AUTH_SPLITERS = ['Basic ', 'Bearer ']
const DEFAULT_CONFIG = {
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
  KEY_FORMAT: 'base64',
  TOKEN_KEY_START_INDEX: 40,
  TOKEN_KEY_END_INDEX: 72
}

export { SECURITY_TYPES as ARGUS_SECURITY_TYPES }
export { AUTH_TYPES as ARGUS_AUTH_TYPES }

export class Argus {
  constructor (config = {}) {
    this.CONFIG = Object.assign({}, DEFAULT_CONFIG, config)

    // Method Hard-Binding
    this.generateKey = this.generateKey.bind(this)
    this.encryptPassword = this.encryptPassword.bind(this)
    this.verifyPassword = this.verifyPassword.bind(this)

    this.createJWT = this.createJWT.bind(this)
    this.decodeJWT = this.decodeJWT.bind(this)
    this.verifyJWT = this.verifyJWT.bind(this)

    this.encryptPayload = this.encryptPayload.bind(this)
    this.decryptPayload = this.decryptPayload.bind(this)

    this.applySecurity = this.applySecurity.bind(this)
    this.validateSecurity = this.validateSecurity.bind(this)

    this.hmacSha256 = this.hmacSha256.bind(this)

    this.cipher = this.cipher.bind(this)
    this.decipher = this.decipher.bind(this)

    this.encode = this.encode.bind(this)
    this.decode = this.decode.bind(this)

    this.decodeAuth = this.decodeAuth.bind(this)
    this._extractAuthToken = this._extractAuthToken.bind(this)
    this._decodeAuthToken = this._decodeAuthToken.bind(this)
    this._decodeBasicAuthToken = this._decodeBasicAuthToken.bind(this)
    this._getKeyFromToken = this._getKeyFromToken.bind(this)
  }

  static get SECURITY_TYPES () { return SECURITY_TYPES }
  static get VERSION () { return VERSION }

  generateKey (length = 16, format = '') {
    const { CONFIG } = this
    const thisLength = length || CONFIG.KEY_LENGTH
    const thisFormat = format || CONFIG.KEY_FORMAT
    return crypto.randomBytes(thisLength).toString(thisFormat)
  }

  encryptPassword (password = '', salt = '') {
    const { CONFIG, hmacSha256 } = this
    const thisSalt = salt || CONFIG.DEFAULT_PASSWORD_SALT
    return hmacSha256(password, thisSalt)
  }

  verifyPassword (password = '', hash = '', salt = '') {
    const { CONFIG, encryptPassword } = this
    const thisSalt = salt || CONFIG.PASSWORD_SALT
    const passwordHash = encryptPassword(password, thisSalt)
    return passwordHash === hash
  }

  createJWT (claims = {}, secret = '') {
    const { CONFIG, encode, hmacSha256 } = this
    const thisSecret = secret || CONFIG.JWT_SECRET
    const encoding = CONFIG.ENCODING
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    }

    const jwtHeader = encode(JSON.stringify(header), encoding)
    const jwtClaims = encode(JSON.stringify(claims), encoding)
    const jwtSignature = hmacSha256((jwtHeader + jwtClaims), thisSecret)

    return [jwtHeader, jwtClaims, jwtSignature].join('.')
  }

  decodeJWT (authToken) {
    const { CONFIG, decode } = this
    const encoding = CONFIG.ENCODING
    let error

    if (!(authToken && authToken.length)) {
      error = new ResponseBody(401, 'Missing/Invalid Authorization')
      return error
    }

    let jwtArray = authToken && authToken.split('.')

    if (jwtArray.length !== 3) {
      error = new ResponseBody(400, 'Invalid Authorization Token')
      return error
    }

    let header = decode(jwtArray[0], encoding)
    let claims = decode(jwtArray[1], encoding)
    let signature = jwtArray[2]

    try {
      header = JSON.parse(header)
      claims = JSON.parse(claims)
    } catch (e) {
      error = new ResponseBody(400, 'Invalid Authorization Token')
      return error
    }

    if (header.constructor.name !== 'Object' || claims.constructor.name !== 'Object') {
      error = new ResponseBody(400, 'Invalid JWT Header/Claims')
      return error
    }

    return { header, claims, signature }
  }

  verifyJWT (decryptedJWT, secret = '') {
    const { CONFIG, encode, hmacSha256 } = this
    const thisSecret = secret || CONFIG.JWT_SECRET
    const encoding = CONFIG.ENCODING
    const header = JSON.stringify(decryptedJWT.header)
    const claims = JSON.stringify(decryptedJWT.claims)
    const signature = decryptedJWT.signature

    let hash = encode((header + claims), encoding)
    hash = hmacSha256(hash, thisSecret)
    return hash === signature
  }

  encryptPayload (plainText = '', secretKey = '') {
    const { CONFIG, cipher } = this
    const thisSecretKey = secretKey || CONFIG.ENCRYPTION_SECRET
    const algorithm = CONFIG.ENCRYPTION_ALGORITHM
    const key = thisSecretKey
    const iv = crypto.randomBytes(CONFIG.IV_LENGTH)
    const bufferFormat = CONFIG.BUFFER_FORMAT
    const encrypted = cipher(algorithm, plainText, key, iv, bufferFormat)
    const payload = iv.toString(bufferFormat) + ':' + encrypted
    return payload
  }

  decryptPayload (payload = '', secretKey = '') {
    const { CONFIG, decipher } = this
    const thisSecretKey = secretKey || CONFIG.ENCRYPTION_SECRET
    if (!payload) { return }

    let payloadParts = payload.split(':')
    if (payloadParts.length !== 2) {
      return 'Invalid Payload'
    }

    try {
      const key = thisSecretKey
      const algorithm = CONFIG.ENCRYPTION_ALGORITHM
      const iv = payloadParts[0]
      const encryptedText = payloadParts[1]
      const bufferFormat = CONFIG.BUFFER_FORMAT
      const decrypted = decipher(algorithm, encryptedText, key, iv, bufferFormat)
      const _body = JSON.parse(decrypted)
      return _body
    } catch (e) {
      return 'Failed Parsing Payload'
    }
  }

  applySecurity (securityType, request, response, callback) {
    const _this = this
    const { decodeJWT, _extractAuthToken } = _this
    const { headers, query } = request
    const { authorization } = headers
    const { token } = query
    const authToken = _extractAuthToken(authorization) || token
    request.token = authToken

    const applySwitch = {
      [SECURITY_TYPES.JWT]: () => {
        const jwt = decodeJWT(authToken)
        const { claims } = jwt

        request.jwt = jwt
        request.user = claims
      },

      [SECURITY_TYPES.JWT_WITH_PAYLOAD_DECRYPTION]: () => {
        const jwt = decodeJWT(authToken)
        const { claims } = jwt

        request.jwt = jwt
        request.user = claims

        request._decryptPayload = true
      }
    }
    const thisSwitch = applySwitch[securityType]

    if (thisSwitch) { thisSwitch(request) }
    process.nextTick(callback)
  }

  validateSecurity (options = {}, request, response, callback) {
    const _this = this
    const { verifyJWT, decryptPayload, _getKeyFromToken } = _this
    const { jwt, user = {}, body, _decryptPayload } = request
    let err, responseBody

    async.waterfall([
      // Validate JWT and Body
      next => {
        if (jwt instanceof ResponseBody) {
          return process.nextTick(() => next(jwt))
        }

        if (body instanceof Error) {
          err = body.toString()
          responseBody = new ResponseBody(500, err, body)
          return process.nextTick(() => next(responseBody))
        }
      },

      // Get User's Secret Key
      next => {
        const { id } = user
        let { getSecretKey } = options

        if (!(getSecretKey instanceof Function)) {
          err = 'Error Getting User Secret Key'
          responseBody = new ResponseBody(500, err)
          return process.nextTick(() => next(err))
        }

        getSecretKey(id, (error, key) => {
          if (error) {
            err = error.toString()
            responseBody = new ResponseBody(500, err, error)
            return next(responseBody)
          }

          next(null, key)
        })
      },

      // Handle JWT
      (key, next) => {
        const jwtValid = verifyJWT(jwt, key)

        if (!jwtValid) {
          err = 'JWT Tampered, Signature does not match'
          responseBody = new ResponseBody(400, err)
          return process.nextTick(() => next(responseBody))
        }

        request.secretKey = key
        return process.nextTick(next)
      },

      // Handle Payload Decryption Key
      next => {
        if (_decryptPayload !== true) { return process.nextTick(next) }

        let { getEncryptionKey } = options
        const { token = '' } = request
        const key = _getKeyFromToken(token)
        request._encryptionKey = key

        if (getEncryptionKey instanceof Function) {
          return getEncryptionKey((error, key) => {
            if (error) {
              err = 'Error Fetching Encryption Key'
              responseBody = new ResponseBody(500, err)
              return next(responseBody)
            }

            request._encryptionKey = key
            next()
          })
        }

        process.nextTick(next)
      },

      // Handle Payload Decryption
      next => {
        if (_decryptPayload !== true) { return process.nextTick(next) }

        const { body, _encryptionKey = '' } = request
        let { payload = '' } = body
        let _body = decryptPayload(payload, _encryptionKey)

        if (typeof _body === 'string') {
          err = _body
          responseBody = new ResponseBody(400, err)
          return process.nextTick(() => next(err))
        } else {
          request.body = (_body && Object.assign({}, body, _body)) || {}
          return process.nextTick(() => next())
        }
      }
    ], error => {
      if (error) { response.body = error }
      callback()
    })
  }

  hmacSha256 (plainText = '', salt = '') {
    const { CONFIG } = this
    const thisSalt = salt || CONFIG.PASSWORD_SALT
    const hmac = crypto.createHmac('sha256', thisSalt)
    const hash = hmac.update(plainText, 'utf8').digest('base64')
    return hash
  }

  cipher (algorithm = '', plainText = '', key = '', iv = '') {
    const { CONFIG } = this
    const thisKey = key || CONFIG.ENCRYPTION_SECRET
    const thisIV = iv || CONFIG.IV
    const bufferFormat = CONFIG.BUFFER_FORMAT

    let keyBuffer = Buffer.from(thisKey)
    let ivBuffer = Buffer.from(thisIV, bufferFormat)
    let cipher = crypto.createCipheriv(algorithm, keyBuffer, ivBuffer)

    let encrypted = cipher.update(plainText)
    encrypted = Buffer.concat([encrypted, cipher.final()])
    encrypted = encrypted.toString(bufferFormat)
    return encrypted
  }

  decipher (algorithm = '', cipherText = '', key = '', iv = '') {
    const { CONFIG } = this
    const thisKey = key || CONFIG.ENCRYPTION_SECRET
    const thisIV = iv || CONFIG.IV
    const bufferFormat = CONFIG.BUFFER_FORMAT

    let keyBuffer = Buffer.from(thisKey)
    let ivBuffer = Buffer.from(thisIV, bufferFormat)
    let cipherBuffer = Buffer.from(cipherText, bufferFormat)
    let decipher = crypto.createDecipheriv(algorithm, keyBuffer, ivBuffer)

    let decrypted = decipher.update(cipherBuffer)
    decrypted = Buffer.concat([decrypted, decipher.final()])
    decrypted = decrypted.toString()
    return decrypted
  }

  encode (plainText = '', encoding = '') {
    const { CONFIG } = this
    const thisEncoding = encoding || CONFIG.ENCODING
    return Buffer.from(plainText).toString(thisEncoding)
  }

  decode (cipherText = '', encoding = '') {
    const { CONFIG } = this
    const thisEncoding = encoding || CONFIG.ENCODING
    return Buffer.from(cipherText, thisEncoding).toString('utf8')
  }

  decodeAuth (authType, auth) {
    const { _extractAuthToken, _decodeAuthToken } = this
    const authTypeValues = Object.keys(AUTH_TYPES).map(type => AUTH_TYPES[type])
    let error

    if (authTypeValues.indexOf(authType) === -1) {
      error = new ResponseBody(400, "Invalid 'authType' for Decoding")
      return error
    }

    if (!auth) {
      error = new ResponseBody(400, 'Auth Not Found')
      return error
    }

    const token = _extractAuthToken(auth)
    if (!token) {
      error = new ResponseBody(400, 'Invalid Auth')
      return error
    }

    let credentials = _decodeAuthToken(authType, token)
    if (!credentials) {
      error = new ResponseBody(400, 'Invalid Auth Credentials')
      return error
    }

    return credentials
  }

  _extractAuthToken (auth) {
    let parts, token

    AUTH_SPLITERS.forEach(spliter => {
      if (token) { return }
      parts = auth.split(spliter)
      if (parts[0] === '' && parts[1]) {
        token = parts[1]
      }
    })
    return token
  }

  _decodeAuthToken (authType, token = '') {
    const { _decodeBasicAuthToken } = this
    let credentials
    if (authType === AUTH_TYPES.BASIC) {
      credentials = _decodeBasicAuthToken(token)
    }
    return credentials
  }

  _decodeBasicAuthToken (token = '') {
    const { CONFIG } = this
    const { USERNAME_PROP, PASSWORD_PROP } = CONFIG
    let error, credentialParts, credentials
    const encoding = 'base64'

    credentialParts = this.decode(token, encoding)
    credentialParts = credentialParts.split(':')
    if (credentialParts.length !== 2) {
      error = new ResponseBody(400, 'Invalid Auth Token')
    }

    credentials = {
      [USERNAME_PROP]: credentialParts[0],
      [PASSWORD_PROP]: credentialParts[1]
    }

    return error || credentials
  }

  _getKeyFromToken(token = '') {
    const { CONFIG } = this
    const { TOKEN_KEY_START_INDEX, TOKEN_KEY_END_INDEX } = CONFIG
    let key = ''

    if (!token) { return key }

    key = token.substring(TOKEN_KEY_START_INDEX, TOKEN_KEY_END_INDEX)
    return key
  }
}
