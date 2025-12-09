import bcrypt from 'bcryptjs'
import { UserModel } from '../models/User.js'
import { JwtService } from '../services/JwtService.js'
import { HttpError } from '../core/HttpError.js'

class AuthController {
  async login(req, res, next) {
    try {
      const { email, password } = req.body
      const r = await UserModel.findByEmail(email)
      if (!r.rows.length) throw new HttpError(400, 'InvalidCredentials')

      const user = r.rows[0]
      const isValid = await bcrypt.compare(password, user.password_hash)
      if (!isValid) throw new HttpError(400, 'InvalidCredentials')

      const token = JwtService.signUser(user)

      return res.json({ ok: true, token, user })
    } catch (e) { next(e) }
  }

  async register(req, res, next) {
    try {
      const { email, password } = req.body

      const exists = await UserModel.findByEmail(email)
      if (exists.rows.length) throw new HttpError(400, 'EmailExists')

      const hash = await bcrypt.hash(password, 10)
      const r = await UserModel.create(email, hash)
      const user = r.rows[0]
      const token = JwtService.signUser(user)

      res.json({ ok: true, token, user })
    } catch (e) { next(e) }
  }
}

export const authController = new AuthController()
