import * as service from '../services/basic-auth-service'
import { NextFunction, Request, Response } from 'express'

export const signIn = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await service
    .signIn(req, res, next)
    .then((response) => res.json(response))
    .catch((err) => next(err))
}

export const signUp = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await service
    .signUp(req, res, next)
    .then((response) => res.json(response))
    .catch((err) => next(err))
}

export const signOut = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await service
    .signOut(req, res, next)
    .then((response) => res.send(response))
    .catch((err) => next(err))
}

export const forgotPassword = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await service
    .forgotPassword(req, next)
    .then((response) => res.send(response))
    .catch((err) => next(err))
}

export const checkAuthenticated = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await service
    .checkAuthenticated(req, next)
    .then((response) => res.send(response))
    .catch((err) => next(err))
}

export const refreshSession = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await service
    .refreshSession(req, res, next)
    .then((response) => res.send(response))
    .catch((err) => next(err))
}
