import ErrorActionRequired from './error-action-required'
class HttpError extends Error {
  code: number
  details: string
  actionRequired: ErrorActionRequired
  constructor(
    message: string,
    details: string,
    code: number,
    actionRequired?: ErrorActionRequired
  ) {
    super(message)
    this.code = code
    this.details = details
    this.actionRequired = actionRequired ?? ErrorActionRequired.NONE
  }
}

export default HttpError
