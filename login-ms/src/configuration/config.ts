class Config {
  static env = (): string => process.env.NODE_ENV || 'development'

  static port = (): number => Number(process.env.PORT) || 3010

  static jwtSecret = (): string =>
    process.env.JWT_SECRET || '5F86D1E0-0F59-4E88-A766-7E0C10E550A0'

  static mongoConnString = (): string =>
    `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@${process.env.MONGO_URI}/?retryWrites=true&w=majority` ||
    ''
}

export default Config
