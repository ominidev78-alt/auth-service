export function notFoundHandler(req, res, next) {
  res.status(404).json({ ok: false, error: 'NotFound' })
}

export function globalErrorHandler(err, req, res, next) {
  const status = err.status || 500
  res.status(status).json({
    ok: false,
    error: err.message,
    extra: err.extra || null
  })
}
