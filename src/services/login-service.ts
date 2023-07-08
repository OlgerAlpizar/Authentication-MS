import { Logger } from '../configuration/logger'
import { NextFunction, Request } from 'express'
import { UserSchemaModel } from '../models/schema/user-schema'
import { getValidationErrors } from '../configuration/middlewares/errorHandler/validation-errors'
import { jwtExpiresIn, jwtSecret } from '../configuration/settings'
import { validationResult } from 'express-validator'
import AuthResponse from '../models/responses/auth-response'
import HttpError from '../configuration/middlewares/errorHandler/http-error'
import SignInRequest from '../models/requests/sign-in-request'
import SignUpRequest from '../models/requests/sign-up-request'
import User from '../models/entities/user'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const generateToken = (user: User) => {
  const token = jwt.sign(
    {
      email: user.email,
    },
    jwtSecret(),
    {
      expiresIn: jwtExpiresIn(),
    }
  )

  return {
    token: token,
    firstName: user.firstName,
    lastName: user.lastName,
    avatar: user.avatar,
    email: user.email,
    expiresIn: jwtExpiresIn() / 60, //to export as minutes
  }
}

export const signIn = async (
  req: Request,
  next: NextFunction
): Promise<AuthResponse | void> => {
  const request: SignInRequest = req.body
  const validationErrors = validationResult(req).array()

  if (validationErrors.length > 0) {
    return next(
      new HttpError(
        'Error validating user data',
        getValidationErrors(validationErrors),
        403
      )
    )
  }

  const existingUser = await UserSchemaModel.findOne({ email: request.email })

  if (!existingUser) {
    return next(new HttpError(`User ${request.email} does not exists`, '', 404))
  }

  const checkPass = await bcrypt.compare(
    request.password,
    existingUser.password
  )
  if (!checkPass) {
    return next(new HttpError('Incorrect password', '', 401))
  }

  return generateToken(existingUser)
}

export const signUp = async (
  req: Request,
  next: NextFunction
): Promise<AuthResponse | void> => {
  const request: SignUpRequest = req.body
  const validationErrors = validationResult(req).array()

  Logger.info('here')

  if (validationErrors.length > 0) {
    return next(
      new HttpError(
        'Error validating data for new account',
        getValidationErrors(validationErrors),
        422
      )
    )
  }

  const exists = await UserSchemaModel.findOne({ email: request.email })

  if (exists) {
    return next(new HttpError('Email user already exists', request.email, 422))
  }

  const newUser = new UserSchemaModel(request)
  newUser.password = await bcrypt.hash(newUser.password, 12)

  const storedUser = await newUser.save().then((res) => {
    return res.id
  })

  return generateToken(storedUser)
}

export const signOut = async (
  req: Request,
  next: NextFunction
): Promise<boolean | void> => {
  const requester = req.headers.userEmail as string

  const exists = await UserSchemaModel.findOne({ email: requester })

  if (!exists) {
    return next(
      new HttpError(
        `User ${requester} does not exists. Then cannot logout`,
        requester,
        404
      )
    )
  }

  return true
}

export const forgotPassword = async (
  req: Request,
  next: NextFunction
): Promise<boolean | void> => {
  const request = req.body
  const validationErrors = validationResult(req).array()

  if (validationErrors.length > 0) {
    return next(
      new HttpError(
        'Error validating user email',
        getValidationErrors(validationErrors),
        403
      )
    )
  }

  const existingUser = await UserSchemaModel.findOne({ email: request.email })

  if (!existingUser) {
    return next(new HttpError(`User ${request.email} does not exists`, '', 404))
  }

  //TODO: Implement logic for password reset

  return true
}

export const checkAuthenticated = async (
  req: Request,
  next: NextFunction
): Promise<boolean | void> => {
  const requester = req.headers.userEmail as string

  const exists = await UserSchemaModel.findOne({ email: requester })

  if (!exists) {
    return next(
      new HttpError(
        `User ${requester} does not exists. Then cannot logout`,
        requester,
        404
      )
    )
  }

  return true
}
