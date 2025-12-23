import Joi from 'joi';
import QRCode from 'qrcode';
import { UserModel } from '../models/UserModel.js';
import { TwoFactorAuthModel } from '../models/TwoFactorAuthModel.js';
import { TotpService } from '../services/TotpService.js';
import { HttpError } from '../core/HttpError.js';
import { env } from '../config/env.js';

const setupSchema = Joi.object({
  method: Joi.string().valid('TOTP').default('TOTP'),
  method: Joi.string().valid('TOTP').default('TOTP')
})

const verifySchema = Joi.object({
  code: Joi.string().length(6).pattern(/^\d+$/).required()
})

const disableSchema = Joi.object({
  code: Joi.string().length(6).pattern(/^\d+$/).required()
})

export class TwoFactorAuthController {
  /**
   * Start 2FA setup process
   */
  async setup(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const { value, error } = setupSchema.validate(req.body)
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details })
      }

      const { method } = value

      // Check if already enabled
      const existing = await TwoFactorAuthModel.findByUserId(userId)
      if (existing?.enabled) {
        throw new HttpError(400, 'TwoFactorAlreadyEnabled', {
          message: 'O segundo fator de autenticação já está ativo.'
        })
      }

      // Generate new secret
      const secret = TotpService.generateSecret()
      const user = req.user

      // Standardize issuer name
      const issuer = 'Pagandu Fintech'
      const otpAuthUrl = TotpService.generateOtpAuthUrl(secret, user.email, issuer)

      // Save secret (but not enabled yet)
      await TwoFactorAuthModel.upsert({
        userId,
        method,
        secret,
        enabled: false,
        verified: false
      })

      // Generate QR Code as data URL
      const qrCodeDataUrl = await QRCode.toDataURL(otpAuthUrl)

      // Log setup start
      const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
      const userAgent = req.headers['user-agent'] || null

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'SETUP_STARTED',
        method,
        ipAddress,
        userAgent,
        success: true
      })

      return res.json({
        ok: true,
        secret, // Show secret to user for manual entry
        qrCode: qrCodeDataUrl,
        method
      })
    } catch (err) {
      return next(err)
    }
  }

  /**
   * Verify and enable 2FA
   */
  async enable(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const { value, error } = verifySchema.validate(req.body)
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details })
      }

      const { code } = value

      const config = await TwoFactorAuthModel.findByUserId(userId)
      if (!config || config.secret === null) {
        throw new HttpError(400, 'SetupNotStarted', {
          message: 'Configuração de 2FA não iniciada.'
        })
      }

      if (config.enabled) {
        throw new HttpError(400, 'TwoFactorAlreadyEnabled')
      }

      // Verify token
      const isValid = TotpService.verifyToken(code, config.secret)
      if (!isValid) {
        const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
        const userAgent = req.headers['user-agent'] || null

        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'ENABLE_FAILED',
          method: config.method,
          ipAddress,
          userAgent,
          success: false,
          failureReason: 'Invalid code'
        })

        throw new HttpError(400, 'InvalidCode', {
          message: 'Código de verificação inválido.'
        })
      }

      // Enable 2FA
      await TwoFactorAuthModel.enable(userId)

      // Generate recovery codes
      const recoveryCodes = TotpService.generateRecoveryCodes(10)
      await TwoFactorAuthModel.saveRecoveryCodes(userId, recoveryCodes)

      // Log success
      const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
      const userAgent = req.headers['user-agent'] || null

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'ENABLED',
        method: config.method,
        ipAddress,
        userAgent,
        success: true
      })

      return res.json({
        ok: true,
        message: 'Segundo fator de autenticação ativado com sucesso.',
        recoveryCodes // Show only once
      })
    } catch (err) {
      return next(err)
    }
  }

  /**
   * Disable 2FA
   */
  async disable(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const { value, error } = disableSchema.validate(req.body)
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details })
      }

      const { code } = value

      const config = await TwoFactorAuthModel.findByUserId(userId)
      if (!config || !config.enabled) {
        throw new HttpError(400, 'TwoFactorNotEnabled')
      }

      // Verify token
      const isValid = TotpService.verifyToken(code, config.secret)
      if (!isValid) {
        const failure = await TwoFactorAuthModel.recordFailure(userId)

        const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
        const userAgent = req.headers['user-agent'] || null

        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'DISABLE_FAILED',
          method: config.method,
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

      // Disable 2FA
      await TwoFactorAuthModel.disable(userId)

      // Log success
      const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
      const userAgent = req.headers['user-agent'] || null

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'DISABLED',
        method: config.method,
        ipAddress,
        userAgent,
        success: true
      })

      return res.json({
        ok: true,
        message: 'Segundo fator de autenticação desativado.'
      })
    } catch (err) {
      return next(err)
    }
  }

  /**
   * Get 2FA status
   */
  async status(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const config = await TwoFactorAuthModel.findByUserId(userId)
      const recoveryCodesCount = await TwoFactorAuthModel.getRecoveryCodesCount(userId)

      return res.json({
        ok: true,
        enabled: config?.enabled || false,
        method: config?.method || null,
        lastUsed: config?.last_used_at || null,
        recoveryCodesRemaining: recoveryCodesCount
      })
    } catch (err) {
      return next(err)
    }
  }

  /**
   * Verify code (used for sensitive operations or re-login)
   */
  async verify(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const { value, error } = verifySchema.validate(req.body)
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details })
      }

      const { code } = value

      const config = await TwoFactorAuthModel.findByUserId(userId)
      if (!config || !config.enabled) {
        throw new HttpError(400, 'TwoFactorNotEnabled')
      }

      // Check if locked
      const isLocked = await TwoFactorAuthModel.isLocked(userId)
      if (isLocked) {
        throw new HttpError(423, 'TwoFactorLocked', {
          message: '2FA está temporariamente bloqueado devido a múltiplas tentativas falhas.'
        })
      }

      // Verify token
      const isValid = TotpService.verifyToken(code, config.secret)

      const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
      const userAgent = req.headers['user-agent'] || null

      if (!isValid) {
        const failure = await TwoFactorAuthModel.recordFailure(userId)

        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'VERIFY_FAILED',
          method: config.method,
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

      // Record success
      await TwoFactorAuthModel.recordSuccess(userId)

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'VERIFY_SUCCESS',
        method: config.method,
        ipAddress,
        userAgent,
        success: true
      })

      return res.json({
        ok: true,
        message: 'Código verificado com sucesso.'
      })
    } catch (err) {
      return next(err)
    }
  }

  /**
   * Verify recovery code
   */
  async verifyRecovery(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const { code } = req.body
      if (!code) {
        throw new HttpError(400, 'CodeRequired')
      }

      const config = await TwoFactorAuthModel.findByUserId(userId)
      if (!config || !config.enabled) {
        throw new HttpError(400, 'TwoFactorNotEnabled')
      }

      const isValid = await TwoFactorAuthModel.verifyRecoveryCode(userId, code)

      const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
      const userAgent = req.headers['user-agent'] || null

      if (!isValid) {
        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'RECOVERY_FAILED',
          method: 'RECOVERY_CODE',
          ipAddress,
          userAgent,
          success: false,
          failureReason: 'Invalid recovery code'
        })

        throw new HttpError(400, 'InvalidCode', {
          message: 'Código de recuperação inválido.'
        })
      }

      // Record success
      await TwoFactorAuthModel.recordSuccess(userId)

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'RECOVERY_SUCCESS',
        method: 'RECOVERY_CODE',
        ipAddress,
        userAgent,
        success: true
      })

      return res.json({
        ok: true,
        message: 'Código de recuperação verificado com sucesso.'
      })
    } catch (err) {
      return next(err)
    }
  }

  /**
   * Generate new recovery codes
   */
  async regenerateRecoveryCodes(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const { code } = req.body
      if (!code) {
        throw new HttpError(400, 'CodeRequired', {
          message: 'Código 2FA é necessário para gerar novos códigos de recuperação.'
        })
      }

      const config = await TwoFactorAuthModel.findByUserId(userId)
      if (!config || !config.enabled) {
        throw new HttpError(400, 'TwoFactorNotEnabled')
      }

      // Verify token first
      const isValid = TotpService.verifyToken(code, config.secret)
      if (!isValid) {
        throw new HttpError(400, 'InvalidCode')
      }

      // Generate recovery codes
      const recoveryCodes = TotpService.generateRecoveryCodes(10)
      await TwoFactorAuthModel.saveRecoveryCodes(userId, recoveryCodes)

      // Log success
      const ipAddress = req.ip || req.headers['x-forwarded-for'] || null
      const userAgent = req.headers['user-agent'] || null

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'RECOVERY_CODES_REGENERATED',
        method: config.method,
        ipAddress,
        userAgent,
        success: true
      })

      return res.json({
        ok: true,
        message: 'Novos códigos de recuperação gerados com sucesso.',
        recoveryCodes
      })
    } catch (err) {
      return next(err)
    }
  }

  /**
   * Get audit logs
   */
  async auditLogs(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId
      if (!userId) {
        throw new HttpError(401, 'Unauthorized')
      }

      const logs = await TwoFactorAuthModel.getAuditLogs(userId)

      return res.json({
        ok: true,
        logs: logs.map(log => ({
          action: log.action,
          method: log.method,
          success: log.success,
          ip: log.ip_address,
          createdAt: log.created_at
        }))
      })
    } catch (err) {
      return next(err)
    }
  }
}

export const twoFactorAuthController = new TwoFactorAuthController()
