export const environment = (): string => process.env.NODE_ENV || 'development'

export const serverPort = (): number => Number(process.env.PORT) || 3010

export const jwtSecret = (): string =>
  process.env.JWT_SECRET || '5F86D1E0-0F59-4E88-A766-7E0C10E550A0'

export const jwtExpiresIn = (): number => 900000 //15min

export const mongoConnString = (): string =>
  `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@${process.env.MONGO_URI}/?retryWrites=true&w=majority` ||
  ''

export const whiteListUrls = (): string[] | undefined => process.env.WHITE_LIST_URLS as string[] | undefined