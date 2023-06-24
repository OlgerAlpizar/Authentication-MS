import Config from '../../configuration/config'

class AuthenticationInfo {
  token: string
  expiresIn: string
  type: string

  constructor(token: string) {
    this.token = token
    this.expiresIn = Config.jwtExpiresIn()
    this.type = 'Bearer'
  }
}

export default AuthenticationInfo