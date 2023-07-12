import { Logger } from '../../configuration/logger'
import { NextFunction, Request, Response } from 'express'
import {
  checkUserCredentials,
  getUser,
  saveUser,
} from '../../utils/user-helper'
import {
  deleteCookieOptions,
  refreshTokenCookieOptions,
  signedCookieOptions,
} from '../../utils/cookie-helper'
import {
  getTokenDecode,
  signRefreshToken,
  signSignedToken,
} from '../../utils/jwt-helper'
import { getValidationErrors } from '../../configuration/middlewares/errorHandler/validation-errors'
import { jwtRefreshTokenSecret } from '../../configuration/settings'
import { validationResult } from 'express-validator'
import AuthResponse, {
  getAuthTokenResponse,
} from '../models/responses/auth-response'
import HttpError from '../../configuration/middlewares/errorHandler/http-error'
import SignInRequest from '../models/requests/sign-in-request'
import SignUpRequest from '../models/requests/sign-up-request'

export const signIn = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<AuthResponse | void> => {
  try {
    const request: SignInRequest = req.body
    const validationErrors = validationResult(req).array()

    if (validationErrors.length > 0) {
      throw new Error(getValidationErrors(validationErrors))
    }

    const dbUser = await checkUserCredentials(request.email, request.password)

    res.cookie('signed', signSignedToken(), signedCookieOptions())
    res.cookie(
      'refresh_token',
      signRefreshToken(dbUser),
      refreshTokenCookieOptions()
    )

    return getAuthTokenResponse(dbUser)
  } catch (error) {
    return next(
      new HttpError('Unable to sign in', (error as Error).message, 401)
    )
  }
}
/* ---------------------------------------------------------------------------------------------------- */

export const signUp = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<AuthResponse | void> => {
  try {
    const request: SignUpRequest = req.body
    const validationErrors = validationResult(req).array()

    if (validationErrors.length > 0) {
      throw new Error(getValidationErrors(validationErrors))
    }

    const newUser = await saveUser(request)

    res.cookie('signed', signSignedToken(), signedCookieOptions())
    res.cookie(
      'refresh_token',
      signRefreshToken(newUser),
      refreshTokenCookieOptions()
    )

    return getAuthTokenResponse(newUser)
  } catch (error) {
    return next(
      new HttpError('Unable to sign up', (error as Error).message, 401)
    )
  }
}
/* ---------------------------------------------------------------------------------------------------- */

export const signOut = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<boolean | void> => {
  try {
    await getUser('', req.headers.userEmail as string)

    res.clearCookie('signed', deleteCookieOptions())
    res.clearCookie('refresh_token', deleteCookieOptions())

    return true
  } catch (error) {
    return next(
      new HttpError('Unable to sign out', (error as Error).message, 401)
    )
  }
}
/* ---------------------------------------------------------------------------------------------------- */

export const forgotPassword = async (
  req: Request,
  next: NextFunction
): Promise<boolean | void> => {
  try {
    const request = req.body
    const validationErrors = validationResult(req).array()

    if (validationErrors.length > 0) {
      throw new Error('Error validating user email')
    }

    const dbUser = await getUser('', request.email)
    Logger.info(`Account ${dbUser.email} should be restored`)

    return true
  } catch (error) {
    return next(
      new HttpError('Unable to reset password', (error as Error).message, 401)
    )
  }
}
/* ---------------------------------------------------------------------------------------------------- */

export const checkAuthenticated = async (
  req: Request,
  next: NextFunction
): Promise<boolean | void> => {
  try {
    await getUser('', req.headers.userEmail as string)

    return true
  } catch (error) {
    return next(
      new HttpError(
        'Unable to check authorization',
        (error as Error).message,
        401
      )
    )
  }
}
/* ---------------------------------------------------------------------------------------------------- */

export const refreshSession = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<AuthResponse | void> => {
  try {
    const refreshToken = getTokenDecode(
      req.cookies.refresh_token,
      jwtRefreshTokenSecret()
    )
    const dbUser = await getUser(refreshToken.id, '')

    res.cookie('signed', signSignedToken(), signedCookieOptions())
    res.cookie(
      'refresh_token',
      signRefreshToken(dbUser),
      refreshTokenCookieOptions()
    )

    return getAuthTokenResponse(dbUser)
  } catch (error) {
    return next(
      new HttpError(
        'Unable to refresh the access token',
        (error as Error).message,
        401
      )
    )
  }
}
