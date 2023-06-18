import { NextFunction, Request, Response } from 'express'
import * as service from '../services/login-service'


export const signIn = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await service
    .signIn(req, next)
    .then((response) => res.send(response))
    .catch((err) => next(err))
}

export const signUp = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {  
  await service
    .signUp(req, next)
    .then((response) => res.status(201).send(response))
    .catch((err) => next(err))
}

export const signOut = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await service
    .signOut(req, next)
    .then((response) => res.send(response))
    .catch((err) => next(err))
}
