export const environment = (): string => process.env.NODE_ENV || 'development'

export const serverPort = (): number => Number(process.env.PORT) || 3010

export const jwtAccessTokenSecret = (): string =>
  process.env.JWT_ACCESS_TOKEN_SECRET || ''

export const jwtRefreshTokenSecret = (): string =>
  process.env.JWT_REFRESH_TOKEN_SECRET || ''

export const expirationAccessToken = (): number => 5 //seconds

export const expirationRefreshToken = (): number => 15 // 1day

export const mongoConnString = (): string =>
  `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@${process.env.MONGO_URI}/?retryWrites=true&w=majority` ||
  ''

export const whiteListUrls = (): string[] | undefined =>
  process.env.WHITE_LIST_URLS as string[] | undefined

export const googleClientId = (): string => process.env.GOOGLE_CLIENT_ID || ''

export const googleClientSecret = (): string =>
  process.env.GOOGLE_CLIENT_SECRET || ''
