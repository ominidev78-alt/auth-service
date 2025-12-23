export class HttpError extends Error {
    status;
    extra;
    constructor(status, message, extra = {}) {
        super(message);
        this.status = status;
        this.extra = extra;
    }
}
