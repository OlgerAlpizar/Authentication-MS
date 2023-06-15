class HttpError extends Error {
  code: number
  details: string
  constructor(message: string, details: string, code: number) {
    super(message)
    this.code = code
    this.details = details
  }
}

export default HttpError