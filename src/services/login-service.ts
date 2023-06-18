import HttpError from '../configuration/errorHandler/http-error'
import SignInRequest from '../models/requests/sign-in-request'
import SignOutRequest from '../models/requests/sign-out-request'
import SignUpRequest from '../models/requests/sign-up-request'
import { UserSchemaModel } from '../models/schema/user-schema'
import { NextFunction, Request } from 'express'
import { getValidationErrors } from '../configuration/errorHandler/validation-errors'
import { validationResult } from 'express-validator'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import Config from '../configuration/config'

const generateToken = (email: string, id: string) =>{
  return jwt.sign(
    {userEmail: email, userId: id},
    Config.jwtSecret(),
    {expiresIn: '15m'}
  )
}

export const signIn = async (req: Request, next: NextFunction): Promise<string | void> => {
  const request: SignInRequest = req.body
  const validationErrors = validationResult(req).array()

  if (validationErrors.length > 0) {    
    return next(new HttpError('Error validating user data', getValidationErrors(validationErrors), 403))
  }

  const existingUser = await UserSchemaModel.findOne({email: request.email})

  if(!existingUser){
    return next(new HttpError(`User ${request.email} does not exists`, '', 404))
  }

  if(await bcrypt.compare(existingUser.password, request.password)){
    return next(new HttpError('Incorrect password', '', 401))
  }

  return generateToken(existingUser.email, existingUser.id)
}

export const signUp = async (req: Request, next: NextFunction): Promise<string | void> => {
  const request: SignUpRequest = req.body
  const validationErrors = validationResult(req).array()

  if (validationErrors.length > 0) {    
    return next(new HttpError('Error validating data for new account', getValidationErrors(validationErrors), 422))
  }

  const exists = await UserSchemaModel.findOne({email: request.email})

  if(exists){
    return next(new HttpError('Email user already exists', request.email, 422))
  }

  const newUser = new UserSchemaModel(request)
  newUser.password = await bcrypt.hash(newUser.password , 12)

  const storedUser = await newUser
    .save()
    .then(res => { return res.id})

  return generateToken(storedUser.email, storedUser.id)
}

export const signOut = async (req: Request, next: NextFunction): Promise<boolean | void> => {
  const request: SignOutRequest = req.body
  const validationErrors = validationResult(req).array()

  if (validationErrors.length > 0) {    
    return next(new HttpError('Error validating user data', getValidationErrors(validationErrors), 403))
  }

  const exists = await UserSchemaModel.findOne({email: request.email})

  if(!exists){
    return next(new HttpError(`User ${request.email} does not exists. Then cannot logout`, request.email, 404))
  }

  return true
}