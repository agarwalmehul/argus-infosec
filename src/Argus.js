import crypto from 'crypto'
import async from 'async'
import { ResponseBody } from './ResponseBody'

const VERSION = '0.1.3'
const DEFAULT_PASSWORD_SALT = 'Im Batman!'
const IV_LENGTH = 16
const SECURITY_TYPES = {
  JWT: Symbol('JWT'),
  JWT_WITH_PAYLOAD_ENCRYPTION: Symbol('JWT_WITH_PAYLOAD_ENCRYPTION')
}

export { SECURITY_TYPES as ARGUS_SECURITY_TYPES }

export class Argus {
  constructor (config = {}) {
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
  }

  static get SECURITY_TYPES () { return SECURITY_TYPES }
  static get __version () { return VERSION }

  generateKey (length = 16, format = 'base64') {
    return crypto.randomBytes(length).toString(format)
  }

  encryptPassword (password, salt) {
    const { hmacSha256 } = this
    return hmacSha256(password, salt || DEFAULT_PASSWORD_SALT)
  }

  verifyPassword (password, hash, salt) {
    const { encryptPassword } = this
    const passwordHash = encryptPassword(password, salt)
    return passwordHash === hash
  }

  createJWT (claims, secret) {
    const { encode, hmacSha256 } = this
    const encoding = 'base64'
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    }

    const jwtHeader = encode(JSON.stringify(header), encoding)
    const jwtClaims = encode(JSON.stringify(claims), encoding)
    const jwtSignature = hmacSha256((jwtHeader + jwtClaims), secret)

    return [jwtHeader, jwtClaims, jwtSignature].join('.')
  }

  decodeJWT (authToken) {
    const { decode } = this
    const encoding = 'base64'
    let error, responseBody

    if (!(authToken && authToken.length)) {
      error = 'Missing/Invalid Authorization'
      responseBody = new ResponseBody(401, error)
      return responseBody
    }

    let jwtArray = authToken && authToken.split('.')

    if (jwtArray.length !== 3) {
      error = 'Invalid Authorization Token'
      responseBody = new ResponseBody(400, error)
      return responseBody
    }

    let header = decode(jwtArray[0], encoding)
    let claims = decode(jwtArray[1], encoding)
    let signature = jwtArray[2]

    try {
      header = JSON.parse(header)
      claims = JSON.parse(claims)
    } catch (e) {
      error = 'Invalid Authorization Token'
      responseBody = new ResponseBody(400, error)
      return responseBody
    }

    if (header.constructor.name !== 'Object' || claims.constructor.name !== 'Object') {
      error = 'Invalid JWT Header/Claims'
      responseBody = new ResponseBody(400, error)
      return responseBody
    }

    return { header, claims, signature }
  }

  verifyJWT (decryptedJWT, secret) {
    const { encode, hmacSha256 } = this
    const encoding = 'base64'
    const header = JSON.stringify(decryptedJWT.header)
    const claims = JSON.stringify(decryptedJWT.claims)
    const signature = decryptedJWT.signature

    let hash = encode((header + claims), encoding)
    hash = hmacSha256(hash, secret)
    return hash === signature
  }

  encryptPayload (plainText = '', secretKey = '') {
    const { cipher } = this
    const algorithm = 'aes-256-cbc'
    const key = secretKey.substring(16, 48)
    const iv = crypto.randomBytes(IV_LENGTH)
    const bufferFormat = 'hex'
    const encrypted = cipher(algorithm, plainText, key, iv, bufferFormat)
    const payload = iv.toString(bufferFormat) + ':' + encrypted
    return payload
  }

  decryptPayload (payload = '', secretKey = '') {
    const { decipher } = this
    if (!payload) { return }

    let payloadParts = payload.split(':')
    if (payloadParts.length !== 2) {
      return 'Invalid Payload'
    }

    try {
      const key = secretKey.substring(16, 48)
      const algorithm = 'aes-256-cbc'
      const iv = payloadParts[0]
      const encryptedText = payloadParts[1]
      const bufferFormat = 'hex'
      const decrypted = decipher(algorithm, encryptedText, key, iv, bufferFormat)
      const _body = JSON.parse(decrypted)
      return _body
    } catch (e) {
      return 'Failed Parsing Payload'
    }
  }

  applySecurity (securityType, request, response, callback) {
    const _this = this
    const { decodeJWT } = _this
    const { headers, query } = request
    const { authorization } = headers
    const { token } = query
    const authToken = (authorization && authorization.split('Bearer ')[1]) || token
    request.token = authToken

    const applySwitch = {
      [SECURITY_TYPES.JWT]: () => {
        const jwt = decodeJWT(authToken)
        const { claims } = jwt

        request.jwt = jwt
        request.user = claims
      },

      [SECURITY_TYPES.JWT_WITH_PAYLOAD_ENCRYPTION]: () => {
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
    const { verifyJWT, decryptPayload } = _this
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
        const key = token && token.substring(16, 48)
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
    const hmac = crypto.createHmac('sha256', salt)
    const hash = hmac.update(plainText, 'utf8').digest('base64')
    return hash
  }

  cipher (algorithm = '', plainText = '', key = '', iv = '', bufferFormat = 'hex') {
    let keyBuffer = Buffer.from(key)
    let ivBuffer = Buffer.from(iv, bufferFormat)
    let cipher = crypto.createCipheriv(algorithm, keyBuffer, ivBuffer)

    let encrypted = cipher.update(plainText)
    encrypted = Buffer.concat([encrypted, cipher.final()])
    encrypted = encrypted.toString(bufferFormat)
    return encrypted
  }

  decipher (algorithm = '', cipherText = '', key = '', iv = '', bufferFormat = 'hex') {
    let keyBuffer = Buffer.from(key)
    let ivBuffer = Buffer.from(iv, bufferFormat)
    let cipherBuffer = Buffer.from(cipherText, bufferFormat)
    let decipher = crypto.createDecipheriv(algorithm, keyBuffer, ivBuffer)

    let decrypted = decipher.update(cipherBuffer)
    decrypted = Buffer.concat([decrypted, decipher.final()])
    decrypted = decrypted.toString()
    return decrypted
  }

  encode (plainText = '', encoding = 'base64') {
    return Buffer.from(plainText).toString(encoding)
  }

  decode (cipherText = '', encoding = 'base64') {
    return Buffer.from(cipherText, encoding).toString('utf8')
  }
}
