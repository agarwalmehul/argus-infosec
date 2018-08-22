import { Argus, ARGUS_SECURITY_TYPES } from './Argus'
import { ResponseBody } from './ResponseBody'

const argus = new Argus()

export class ExpressRouteHelper {
  constructor({ AuthModel, SUPERADMIN_ROLE }) {
    this.AuthModel = AuthModel
    this.SUPERADMIN_ROLE = SUPERADMIN_ROLE

    // Method Hard-binding
    this.applyJWT = this.applyJWT.bind(this)
    this.applyJWTandEncryption = this.applyJWTandEncryption.bind(this)
    this.validateSecurity = this.validateSecurity.bind(this)
    this.manageSelfAccess = this.manageSelfAccess.bind(this)
    this.manageSuperadminAccess = this.manageSuperadminAccess.bind(this)
    this.responseBody = this.responseBody.bind(this)
    this.sendEncryptedResponse = this.sendEncryptedResponse.bind(this)
  }

  applyJWT (request, response, next) {
    argus.applySecurity(ARGUS_SECURITY_TYPES.JWT, request, response, next)
  }

  applyJWTandEncryption (request, response, next) {
    argus.applySecurity(ARGUS_SECURITY_TYPES.JWT_WITH_PAYLOAD_ENCRYPTION, request, response, next)
  }

  validateSecurity (request, response, next) {
    const { AuthModel } = this
    const { getSecretKey } = AuthModel
    const options = { getSecretKey }
    argus.validateSecurity(options, request, response, next)
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
    const { SUPERADMIN_ROLE } = this
    const { user = {} } = request
    const { role = '', roles = [] } = user
    let isSuperAdmin = role === SUPERADMIN_ROLE || roles.indexOf(SUPERADMIN_ROLE) > -1

    if (!isSuperAdmin) {
      const error = new ResponseBody(403, 'Forbidden')
      response.body = error
    }

    process.nextTick(next)
  }

  sendResponse(request, response, next) {
    const { body } = response
    response.status(body.statusCode).json(body)
  }

  sendEncryptedResponse(request, response, next) {
    const responseBody = response.body
    const encryptionKey = response._encryptionKey || request._encryptionKey
    const token = response.token || request.token

    const payload = aegis.encryptPayload(responseBody, token)
    const body = { token, payload }
    response.status(200).json(body)
  }
}
