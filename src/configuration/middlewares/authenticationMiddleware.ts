import { NextFunction, Request, Response } from 'express'
import { jwtSecret } from '../settings'
import HttpError from './errorHandler/http-error'
import jwt from 'jsonwebtoken'

const AuthenticationMiddleware = (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    if (req.method === 'OPTIONS') {
      // avoid produce options blocks
      return next()
    }
    const token = req.headers.authorization?.split(' ')[1] //since token usually come as: 'Bearer token'

    if (!token) {
      throw new Error(`Unable to identify auth token ${token}`)
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const decodedToken: any = jwt.verify(token, jwtSecret())
    req.headers.userEmail = decodedToken.email

    next()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    return next(new HttpError('Unauthorized', err.message, 401))
  }
}

export default AuthenticationMiddleware
