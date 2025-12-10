import Joi from 'joi'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { UserModel } from '../models/UserModel.js'
import { TwoFactorAuthModel } from '../models/TwoFactorAuthModel.js'
import { TotpService } from '../services/TotpService.js'
import { env } from '../config/env.js'
import { HttpError } from '../core/HttpError.js'

const registerSchema = Joi.object({
  personType: Joi.string().valid('PF', 'PJ').required(),
  name: Joi.string().min(2).when('personType', {
    is: 'PF',
    then: Joi.required(),
    otherwise: Joi.optional().allow('', null)
  }),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  document: Joi.string().when('personType', {
    is: 'PF',
    then: Joi.required(),
    otherwise: Joi.optional().allow(null, '')
  }),
  cnpj: Joi.string().when('personType', {
    is: 'PJ',
    then: Joi.required(),
    otherwise: Joi.optional().allow(null, '')
  }),
  companyName: Joi.string().when('personType', {
    is: 'PJ',
    then: Joi.required(),
    otherwise: Joi.optional().allow(null, '')
  }),
  tradeName: Joi.string().allow('', null),
  partnerName: Joi.string().allow('', null),
  externalId: Joi.string().allow('', null)
})

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  code: Joi.string().length(6).pattern(/^\d+$/).optional(),
  recoveryCode: Joi.string().optional()
})

const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().min(6).required(),
  newPassword: Joi.string().min(6).required(),
  code: Joi.string().length(6).pattern(/^\d+$/).optional(),
  recoveryCode: Joi.string().optional()
})

const JWT_USER_SECRET = env.JWT_USER_SECRET || 'mutual-secret-2025'
const JWT_ADMIN_SECRET = env.JWT_ADMIN_SECRET || 'mutual-admin-secret-2025'

export class UserAuthController {
  async register(req, res, next) {
    try {
      const { value, error } = registerSchema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true
      })

      if (error) {
        throw new HttpError(400, 'Payload inválido', { details: error.details })
      }

      let {
        name,
        email,
        password,
        personType,
        document,
        cnpj,
        companyName,
        tradeName,
        partnerName,
        externalId
      } = value

      if (personType === 'PJ') {
        if (!name || String(name).trim() === '') {
          name = partnerName || companyName
        }
      }

      if (!partnerName || String(partnerName).trim() === '') {
        partnerName = name || companyName
      }

      // Normalizar email para lowercase antes de verificar e criar
      const normalizedEmail = email ? String(email).toLowerCase().trim() : null
      if (!normalizedEmail) {
        throw new HttpError(400, 'E-mail inválido')
      }

      const existing = await UserModel.findByEmail(normalizedEmail)
      if (existing) {
        throw new HttpError(409, 'E-mail já cadastrado')
      }

      const passwordHash = await bcrypt.hash(password, 10)

      const user = await UserModel.createWithPassword({
        name,
        email: normalizedEmail,
        passwordHash,
        document: personType === 'PF' ? document : null,
        cnpj: personType === 'PJ' ? cnpj : null,
        companyName: personType === 'PJ' ? companyName : null,
        tradeName: personType === 'PJ' ? tradeName || companyName : null,
        partnerName: partnerName || name,
        externalId: externalId || null
      })

      // Gera credenciais automaticamente para novos usuários
      let appId = user.app_id || null
      let clientSecret = user.client_secret || null

      if (!appId || !clientSecret) {
        console.log('[UserAuthController.register] Gerando credenciais para novo usuário:', user.id)
        const generated = await UserModel.generateAndUpdateCredentials(user.id)
        appId = generated.appId
        clientSecret = generated.clientSecret
      }

      const payload = {
        sub: user.id,
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        status: user.status,
        docStatus: user.doc_status,
        personType
      }

      const token = jwt.sign(payload, JWT_USER_SECRET, { expiresIn: '12h' })

      return res.status(201).json({
        ok: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          status: user.status,
          doc_status: user.doc_status,
          personType,
          document: user.document,
          cnpj: user.cnpj,
          companyName: user.company_name,
          tradeName: user.trade_name,
          partnerName: user.partner_name,
          role: user.role
        },
        appId: appId,
        clientSecret: clientSecret
      })
    } catch (err) {
      return next(err)
    }
  }

  async login(req, res, next) {
    try {
      const { value, error } = loginSchema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true
      })

      if (error) {
        throw new HttpError(400, 'Payload inválido', { details: error.details })
      }

      const { email, password, code, recoveryCode } = value
      
      // Normalizar email para lowercase antes de buscar
      const normalizedEmail = email ? String(email).toLowerCase().trim() : null
      if (!normalizedEmail) {
        throw new HttpError(401, 'Credenciais inválidas')
      }
      
      const user = await UserModel.findByEmail(normalizedEmail)

      if (!user || !user.password_hash) {
        console.log('[UserAuthController.login] Usuário não encontrado ou sem senha:', {
          email: normalizedEmail,
          userExists: !!user,
          hasPassword: user ? !!user.password_hash : false
        })
        throw new HttpError(401, 'Credenciais inválidas')
      }

      // Validação de status - permite PENDING, ACTIVE e NULL (novos usuários)
      // Bloqueia apenas se status for explicitamente 'INACTIVE' ou 'BLOCKED'
      if (user.status && ['INACTIVE', 'BLOCKED'].includes(user.status.toUpperCase())) {
        console.log('[UserAuthController.login] Usuário bloqueado ou inativo:', {
          userId: user.id,
          status: user.status
        })
        throw new HttpError(403, 'Usuário bloqueado ou inativo', { status: user.status })
      }

      // Validação de doc_status - permite PENDING para login
      // Bloqueia apenas se estiver explicitamente REJECTED
      if (user.doc_status && user.doc_status.toUpperCase() === 'REJECTED') {
        console.log('[UserAuthController.login] Documentação rejeitada:', {
          userId: user.id,
          docStatus: user.doc_status
        })
        throw new HttpError(403, 'Documentação rejeitada. Entre em contato com o suporte.', { docStatus: user.doc_status })
      }

      const passwordOk = await bcrypt.compare(password, user.password_hash)
      if (!passwordOk) {
        console.log('[UserAuthController.login] Senha incorreta:', {
          userId: user.id,
          email: normalizedEmail
        })
        throw new HttpError(401, 'Credenciais inválidas')
      }

      console.log('[UserAuthController.login] Senha válida, prosseguindo com 2FA se necessário')

      // Check if 2FA is enabled
      const twoFactorConfig = await TwoFactorAuthModel.findByUserId(user.id)
      const twoFactorEnabled = twoFactorConfig?.enabled || false

      if (twoFactorEnabled) {
        // 2FA is required - verify code
        if (!code && !recoveryCode) {
          return res.status(200).json({
            ok: false,
            requires2FA: true,
            message: 'Código 2FA é obrigatório'
          })
        }

        // Check if locked
        const isLocked = await TwoFactorAuthModel.isLocked(user.id)
        if (isLocked) {
          throw new HttpError(423, 'TwoFactorLocked', {
            message: '2FA está temporariamente bloqueado devido a múltiplas tentativas falhas'
          })
        }

        let isValid = false

        if (recoveryCode) {
          isValid = await TwoFactorAuthModel.verifyRecoveryCode(user.id, recoveryCode)
        } else if (code) {
          isValid = TotpService.verifyToken(code, twoFactorConfig.secret)
        }

        if (!isValid) {
          const failure = await TwoFactorAuthModel.recordFailure(user.id)
          
          const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
          const userAgent = req.headers['user-agent'] || null

          await TwoFactorAuthModel.addAuditLog({
            userId: user.id,
            action: 'LOGIN_2FA_FAILED',
            method: 'TOTP',
            context: 'LOGIN',
            ipAddress,
            userAgent,
            success: false,
            failureReason: 'Invalid code'
          })

          if (failure.locked) {
            throw new HttpError(423, 'TwoFactorLocked', {
              message: 'Muitas tentativas falhas. 2FA bloqueado temporariamente.'
            })
          }

          throw new HttpError(400, 'InvalidCode', {
            message: 'Código 2FA inválido',
            attemptsRemaining: 3 - failure.attempts
          })
        }

        // Record successful 2FA verification
        await TwoFactorAuthModel.recordSuccess(user.id)

        const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
        const userAgent = req.headers['user-agent'] || null

        await TwoFactorAuthModel.addAuditLog({
          userId: user.id,
          action: 'LOGIN_2FA_SUCCESS',
          method: 'TOTP',
          context: 'LOGIN',
          ipAddress,
          userAgent,
          success: true
        })
      }

      // Garante que o usuário tenha credenciais (app_id e client_secret)
      let appId = user.app_id || null
      let clientSecret = user.client_secret || null

      if (!appId || !clientSecret) {
        console.log('[UserAuthController.login] Gerando credenciais para usuário sem app_id/client_secret:', user.id)
        const generated = await UserModel.generateAndUpdateCredentials(user.id)
        appId = generated.appId
        clientSecret = generated.clientSecret
        
        // Atualiza o objeto user com as novas credenciais
        user.app_id = appId
        user.client_secret = clientSecret
      }

      const payload = {
        sub: user.id,
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        status: user.status,
        docStatus: user.doc_status
      }

      const token = jwt.sign(payload, JWT_USER_SECRET, { expiresIn: '12h' })

      return res.json({
        ok: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          status: user.status,
          doc_status: user.doc_status,
          document: user.document,
          cnpj: user.cnpj,
          companyName: user.company_name,
          tradeName: user.trade_name,
          partnerName: user.partner_name,
          role: user.role
        },
        appId: appId,
        clientSecret: clientSecret
      })
    } catch (err) {
      return next(err)
    }
  }

  async adminLogin(req, res, next) {
    try {
      const { value, error } = loginSchema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true
      })

      if (error) {
        throw new HttpError(400, 'Payload inválido', { details: error.details })
      }

      const { email, password } = value
      const user = await UserModel.findByEmail(email)

      if (!user || !user.password_hash) {
        throw new HttpError(401, 'Credenciais inválidas')
      }

      if (user.role !== 'ADMIN') {
        throw new HttpError(403, 'Acesso negado')
      }

      const passwordOk = await bcrypt.compare(password, user.password_hash)
      if (!passwordOk) {
        throw new HttpError(401, 'Credenciais inválidas')
      }

      const payload = {
        sub: user.id,
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }

      const token = jwt.sign(payload, JWT_ADMIN_SECRET, { expiresIn: '12h' })

      return res.json({
        ok: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      })
    } catch (err) {
      return next(err)
    }
  }

  async changePassword(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const { value, error } = changePasswordSchema.validate(req.body, {
        abortEarly: false,
        stripUnknown: true
      })

      if (error) {
        throw new HttpError(400, 'Payload inválido', { details: error.details })
      }

      const { currentPassword, newPassword, code, recoveryCode } = value

      const user = await UserModel.findById(userId)
      if (!user || !user.password_hash) {
        throw new HttpError(404, 'UserNotFound')
      }

      // Verify current password
      const passwordOk = await bcrypt.compare(currentPassword, user.password_hash)
      if (!passwordOk) {
        throw new HttpError(401, 'InvalidPassword', {
          message: 'Senha atual incorreta'
        })
      }

      // Check if 2FA is enabled
      const twoFactorConfig = await TwoFactorAuthModel.findByUserId(userId)
      const twoFactorEnabled = twoFactorConfig?.enabled || false

      if (twoFactorEnabled) {
        // 2FA is required - verify code
        if (!code && !recoveryCode) {
          return res.status(200).json({
            ok: false,
            requires2FA: true,
            message: 'Código 2FA é obrigatório para alterar a senha'
          })
        }

        // Check if locked
        const isLocked = await TwoFactorAuthModel.isLocked(userId)
        if (isLocked) {
          throw new HttpError(423, 'TwoFactorLocked', {
            message: '2FA está temporariamente bloqueado devido a múltiplas tentativas falhas'
          })
        }

        let isValid = false

        if (recoveryCode) {
          isValid = await TwoFactorAuthModel.verifyRecoveryCode(userId, recoveryCode)
        } else if (code) {
          isValid = TotpService.verifyToken(code, twoFactorConfig.secret)
        }

        if (!isValid) {
          const failure = await TwoFactorAuthModel.recordFailure(userId)
          
          const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
          const userAgent = req.headers['user-agent'] || null

          await TwoFactorAuthModel.addAuditLog({
            userId,
            action: 'PASSWORD_CHANGE_2FA_FAILED',
            method: 'TOTP',
            context: 'PASSWORD_CHANGE',
            ipAddress,
            userAgent,
            success: false,
            failureReason: 'Invalid code'
          })

          if (failure.locked) {
            throw new HttpError(423, 'TwoFactorLocked', {
              message: 'Muitas tentativas falhas. 2FA bloqueado temporariamente.'
            })
          }

          throw new HttpError(400, 'InvalidCode', {
            message: 'Código 2FA inválido',
            attemptsRemaining: 3 - failure.attempts
          })
        }

        // Record successful 2FA verification
        await TwoFactorAuthModel.recordSuccess(userId)

        const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
        const userAgent = req.headers['user-agent'] || null

        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'PASSWORD_CHANGE_2FA_SUCCESS',
          method: 'TOTP',
          context: 'PASSWORD_CHANGE',
          ipAddress,
          userAgent,
          success: true
        })
      }

      // Hash new password
      const newPasswordHash = await bcrypt.hash(newPassword, 10)

      // Update password
      await UserModel.updatePassword({
        userId,
        passwordHash: newPasswordHash
      })

      // Log password change
      if (twoFactorEnabled) {
        const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
        const userAgent = req.headers['user-agent'] || null

        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'PASSWORD_CHANGED',
          method: 'TOTP',
          context: 'PASSWORD_CHANGE',
          ipAddress,
          userAgent,
          success: true
        })
      }

      return res.json({
        ok: true,
        message: 'Senha alterada com sucesso'
      })
    } catch (err) {
      return next(err)
    }
  }

  // --- Public Forgot Password Flow ---
  async forgotStart(req, res, next) {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase()
      if (!email) throw new HttpError(400, 'E-mail é obrigatório')

      const user = await UserModel.findByEmail(email)
      if (!user) throw new HttpError(404, 'Usuário não encontrado')

      const twoFactorConfig = await TwoFactorAuthModel.findByUserId(user.id)
      const twoFactorEnabled = twoFactorConfig?.enabled || false

      if (!twoFactorEnabled) {
        // For security, require support if 2FA not enabled
        return res.status(400).json({ ok: false, message: '2FA não está ativo para esta conta. Contate o suporte.' })
      }

      return res.json({ ok: true, message: 'Inicie a verificação com seu código 2FA ou código de recuperação.' })
    } catch (err) {
      return next(err)
    }
  }

  async forgotVerify(req, res, next) {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase()
      const code = req.body?.code
      const recoveryCode = req.body?.recoveryCode
      if (!email) throw new HttpError(400, 'E-mail é obrigatório')
      if (!code && !recoveryCode) throw new HttpError(400, 'Informe o código 2FA ou um código de recuperação')

      const user = await UserModel.findByEmail(email)
      if (!user) throw new HttpError(404, 'Usuário não encontrado')

      const twoFactorConfig = await TwoFactorAuthModel.findByUserId(user.id)
      const twoFactorEnabled = twoFactorConfig?.enabled || false
      if (!twoFactorEnabled) throw new HttpError(400, '2FA não está ativo para esta conta')

      // Check lock
      const isLocked = await TwoFactorAuthModel.isLocked(user.id)
      if (isLocked) {
        throw new HttpError(423, 'TwoFactorLocked', {
          message: '2FA está temporariamente bloqueado devido a múltiplas tentativas falhas'
        })
      }

      let isValid = false
      if (recoveryCode) {
        isValid = await TwoFactorAuthModel.verifyRecoveryCode(user.id, recoveryCode)
      } else if (code) {
        isValid = TotpService.verifyToken(code, twoFactorConfig.secret)
      }

      if (!isValid) {
        const failure = await TwoFactorAuthModel.recordFailure(user.id)
        if (failure.locked) {
          throw new HttpError(423, 'TwoFactorLocked', { message: 'Muitas tentativas falhas. 2FA bloqueado temporariamente.' })
        }
        throw new HttpError(400, 'InvalidCode', { message: 'Código 2FA inválido', attemptsRemaining: 3 - failure.attempts })
      }

      await TwoFactorAuthModel.recordSuccess(user.id)

      // Issue short-lived reset token
      const resetToken = jwt.sign({ action: 'PWD_RESET', userId: user.id }, JWT_USER_SECRET, { expiresIn: '15m' })

      return res.json({ ok: true, resetToken })
    } catch (err) {
      return next(err)
    }
  }

  async forgotReset(req, res, next) {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase()
      const resetToken = req.body?.resetToken
      const newPassword = String(req.body?.newPassword || '')
      if (!email) throw new HttpError(400, 'E-mail é obrigatório')
      if (!newPassword || newPassword.length < 6) throw new HttpError(400, 'Nova senha inválida')
      if (!resetToken) throw new HttpError(400, 'resetToken é obrigatório')

      // Verify reset token
      let payload
      try {
        payload = jwt.verify(resetToken, JWT_USER_SECRET)
      } catch (e) {
        throw new HttpError(401, 'ResetToken inválido ou expirado')
      }

      if (payload?.action !== 'PWD_RESET' || !payload?.userId) {
        throw new HttpError(401, 'ResetToken inválido')
      }

      const user = await UserModel.findByEmail(email)
      if (!user || user.id !== payload.userId) {
        throw new HttpError(401, 'ResetToken não corresponde ao usuário')
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10)
      await UserModel.updatePassword({ userId: user.id, passwordHash: newPasswordHash })

      return res.json({ ok: true, message: 'Senha alterada com sucesso' })
    } catch (err) {
      return next(err)
    }
  }
}

export const userAuthController = new UserAuthController()
