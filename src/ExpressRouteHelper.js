import { Argus, ARGUS_SECURITY_TYPES, ARGUS_AUTH_TYPES } from './Argus'
import { ResponseBody } from './ResponseBody'

const DEFAULT_CONFIG = {
  SUPERADMIN_ROLE: 'SUPERADMIN',
  USERNAME_PROP: 'username',
  PASSWORD_PROP: 'password'
}

export class ExpressRouteHelper {
  constructor (AuthModel, CONFIG = {}) {
    this.AuthModel = AuthModel
    this.CONFIG = Object.assign({}, DEFAULT_CONFIG, CONFIG)
    this.argus = new Argus(this.CONFIG)

    // Method Hard-binding
    this.applyJWT = this.applyJWT.bind(this)
    this.applyJWTwithPayloadDecryption = this.applyJWTwithPayloadDecryption.bind(this)
    this.validateSecurity = this.validateSecurity.bind(this)

    this.manageSelfAccess = this.manageSelfAccess.bind(this)
    this.manageSuperadminAccess = this.manageSuperadminAccess.bind(this)

    this.sendResponse = this.sendResponse.bind(this)
    this.sendEncryptedResponse = this.sendEncryptedResponse.bind(this)

    this.decodeBasicAuth = this.decodeBasicAuth.bind(this)
  }

  applyJWT (request, response, next) {
    this.argus.applySecurity(ARGUS_SECURITY_TYPES.JWT, request, response, next)
  }

  applyJWTwithPayloadDecryption (request, response, next) {
    this.argus.applySecurity(ARGUS_SECURITY_TYPES.JWT_WITH_PAYLOAD_DECRYPTION, request, response, next)
  }

  validateSecurity (request, response, next) {
    const { AuthModel } = this
    const { getSecretKey } = AuthModel
    const options = { getSecretKey }
    this.argus.validateSecurity(options, request, response, next)
  }

  manageSelfAccess (request, response, next) {
    const { user = {}, params, body } = request
    const id = params.id || body.id

    if (id !== user.id) {
      const error = new ResponseBody(403, 'Forbidden')
      response.body = error
    }

    process.nextTick(next)
  }

  manageSuperadminAccess (request, response, next) {
    const { CONFIG } = this
    const { SUPERADMIN_ROLE } = CONFIG
    const { user = {} } = request
    const { role = '', roles = [] } = user
    let isSuperAdmin = role === SUPERADMIN_ROLE || roles.indexOf(SUPERADMIN_ROLE) > -1

    if (!isSuperAdmin) {
      const error = new ResponseBody(403, 'Forbidden')
      response.body = error
    }

    process.nextTick(next)
  }

  sendResponse (request, response, next) {
    const { body } = response
    response.status(body.statusCode).json(body)
  }

  sendEncryptedResponse (request, response, next) {
    const { sendResponse } = this
    const { body = {} } = response
    const responseBody = JSON.stringify(body)
    const encryptionKey = response._encryptionKey || request._encryptionKey
    const token = response.token || request.token

    if (!token) { return sendResponse(request, response, next) }

    const payload = this.argus.encryptPayload(responseBody, encryptionKey)
    const _body = { token, payload }
    response.status(200).json(_body)
  }

  decodeBasicAuth (request, response, next) {
    const { headers } = request
    const { authorization } = headers
    const authType = ARGUS_AUTH_TYPES.BASIC
    const credentials = this.argus.decodeAuth(authType, authorization)
    request.body = credentials
    process.nextTick(next)
  }
}
