type StaticOrigin = boolean | string | RegExp | (boolean | string | RegExp)[]
type CorsCallback = (err: Error | null, origins?: StaticOrigin) => void
type OriginType = string | undefined

const whiteList = ['http://localhost:3010', 'http://localhost:3011']

const corsOptions = {
  origin: (origin: OriginType, callback: CorsCallback) => {
    if (!origin) {
      return callback(null, true)
    }
    if (whiteList.indexOf(origin) === -1) {
      return callback(
        new Error(
          'The CORS policy for this site does not allow access from the specified Origin.'
        ),
        false
      )
    }
    return callback(null, true)
  },
}

export default corsOptions
