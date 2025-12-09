export class HttpError extends Error {
  constructor(status, message, extra = null) {
    super(message)
    this.status = status
    this.extra = extra
  }
}
