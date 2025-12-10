import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import { UserModel } from '../models/UserModel.js'
import { env } from '../config/env.js'
import { HttpError } from '../core/HttpError.js'

function generateString(size = 32) {
  return crypto.randomBytes(size).toString('hex')
}

export class AuthController {
  async generateCredentials(req, res, next) {
    try {
      const userId = Number(req.params.id)

      if (!userId || Number.isNaN(userId)) {
        throw new HttpError(400, 'ValidationError', { message: 'userId inválido' })
      }

      const user = await UserModel.findById(userId)
      if (!user) {
        throw new HttpError(404, 'UserNotFound', { userId })
      }

      const appId = `mg_live_${generateString(8)}`
      const clientSecret = `sk_live_${generateString(16)}`
      const hash = crypto.createHash('sha256').update(clientSecret).digest('hex')

      await UserModel.updateCredentials({
        id: userId,
        appId,
        clientSecretHash: hash
      })

      return res.json({
        ok: true,
        userId,
        app_id: appId,
        client_secret: clientSecret
      })
    } catch (err) {
      return next(err)
    }
  }

  async token(req, res, next) {
    try {
      const { appId, clientSecret } = req.body || {}

      if (!appId || !clientSecret) {
        throw new HttpError(400, 'ValidationError', {
          message: 'appId e clientSecret são obrigatórios'
        })
      }

      const user = await UserModel.findByAppId(appId)
      if (!user || !user.client_secret_hash) {
        throw new HttpError(401, 'InvalidCredentials')
      }

      const hash = crypto.createHash('sha256').update(clientSecret).digest('hex')
      if (hash !== user.client_secret_hash) {
        throw new HttpError(401, 'InvalidCredentials')
      }

      const payload = {
        sub: user.id,
        type: 'USER'
      }

      const token = jwt.sign(payload, env.JWT_USER_SECRET, {
        expiresIn: '30m'
      })

      return res.json({
        ok: true,
        accessToken: token,
        userId: user.id
      })
    } catch (err) {
      return next(err)
    }
  }
}

export const authController = new AuthController()
