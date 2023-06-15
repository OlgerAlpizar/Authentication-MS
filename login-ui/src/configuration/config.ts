class Config {
  static loginApi = (): string => {
    return process.env.LOGIN_BACKEND || 'http:localhost'
  }
}

export default Config
