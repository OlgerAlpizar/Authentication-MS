import { NextFunction, Request, Response } from 'express'
import { getTokenDecode } from '../../utils/jwt-helper'
import { jwtAccessTokenSecret } from '../settings'
import ErrorActionRequired from './errorHandler/error-action-required'
import HttpError from './errorHandler/http-error'
import jwt from 'jsonwebtoken'

const verifyToken = (req: Request) => {
  const headers = req.headers.authorization?.split(' ') || []

  if (headers.length > 0 && headers[0].toLowerCase() === 'bearer') {
    return headers[1] //since token usually come as: 'Bearer token'
  }

  throw new Error('No valid bearer token')
}

const AuthenticationMiddleware = (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    if (req.method === 'OPTIONS') {
      return next() // avoid produce options blocks
    }

    const decodedToken = getTokenDecode(
      verifyToken(req),
      jwtAccessTokenSecret()
    )

    req.headers.userId = decodedToken.id
    req.headers.userEmail = decodedToken.email

    next()
  } catch (error) {
    const actionRequired =
      error instanceof jwt.TokenExpiredError
        ? ErrorActionRequired.RE_AUTHENTICATE
        : undefined

    return next(
      new HttpError(
        'Unauthorized',
        (error as Error).message,
        401,
        actionRequired
      )
    )
  }
}

export default AuthenticationMiddleware
