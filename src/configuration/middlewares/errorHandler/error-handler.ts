import { Logger } from '../../logger'
import { NextFunction, Request, Response } from 'express'
import HttpError from './http-error'

const errorHandler = (
  error: HttpError,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
) => {
  Logger.error(`${error.message} - ${error.details}. code: ${error.code}`)
  res.status(error.code || 500).send({
    message: `${error.message || 'Something went wrong'}. ${
      error.details || ''
    }`,
  })
}

export default errorHandler
