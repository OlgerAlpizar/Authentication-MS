import { ValidationError } from 'express-validator'

export const getValidationErrors = (err: ValidationError[]) =>
  `Validation error: ${JSON.stringify(err)}`