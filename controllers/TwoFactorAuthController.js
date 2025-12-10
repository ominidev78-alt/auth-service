import Joi from 'joi';
import QRCode from 'qrcode';
import { UserModel } from '../models/UserModel.js';
import { TwoFactorAuthModel } from '../models/TwoFactorAuthModel.js';
import { TotpService } from '../services/TotpService.js';
import { HttpError } from '../core/HttpError.js';
import { env } from '../config/env.js';

const setupSchema = Joi.object({
  method: Joi.string().valid('TOTP').default('TOTP'),
});

// Accept either a 6-digit TOTP code or a recovery code
const verifySchema = Joi.object({
  code: Joi.string().length(6).pattern(/^\d+$/).optional(),
  recoveryCode: Joi.string().optional(),
}).custom((value, helpers) => {
  if (!value.code && !value.recoveryCode) {
    return helpers.error('any.required', { message: 'Informe code ou recoveryCode' });
  }
  return value;
});

const enableSchema = Joi.object({
  code: Joi.string().length(6).pattern(/^\d+$/).required(),
});

const recoveryCodeSchema = Joi.object({
  code: Joi.string().required(),
});

const JWT_USER_SECRET = env.JWT_USER_SECRET || 'mutual-secret-2025';

export class TwoFactorAuthController {
  /**
   * Initialize 2FA setup - generates secret and QR code
   * POST /api/2fa/setup
   */
  async setup(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId;
      if (!userId) {
        throw new HttpError(401, 'Unauthorized');
      }

      const { value, error } = setupSchema.validate(req.body);
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details });
      }

      const user = await UserModel.findById(userId);
      if (!user) {
        throw new HttpError(404, 'UserNotFound');
      }

      // Check if already enabled
      const existing = await TwoFactorAuthModel.findByUserId(userId);
      if (existing?.enabled) {
        throw new HttpError(400, 'TwoFactorAlreadyEnabled', {
          message: '2FA já está ativado para este usuário',
        });
      }

      // Generate new secret
      const secret = TotpService.generateSecret();

      // Save secret (not enabled yet)
      await TwoFactorAuthModel.upsert({
        userId,
        method: value.method || 'TOTP',
        secret,
        enabled: false,
        verified: false,
      });

      // Generate QR code
      const otpAuthUrl = TotpService.generateOtpAuthUrl(
        secret,
        user.email || `user-${userId}`,
        'Mutual Fintech'
      );

      const qrCodeDataUrl = await QRCode.toDataURL(otpAuthUrl);

      // Log setup initiation
      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'SETUP_INITIATED',
        method: 'TOTP',
        context: JSON.stringify({ email: user.email }),
        ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
        userAgent: req.headers['user-agent'] || null,
        success: true,
      });

      return res.json({
        ok: true,
        secret,
        qrCode: qrCodeDataUrl,
        otpAuthUrl,
        manualEntryKey: secret,
      });
    } catch (err) {
      return next(err);
    }
  }

  /**
   * Verify and enable 2FA
   * POST /api/2fa/enable
   */
  async enable(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId;
      if (!userId) {
        throw new HttpError(401, 'Unauthorized');
      }

      const { value, error } = enableSchema.validate(req.body);
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details });
      }

      const config = await TwoFactorAuthModel.findByUserId(userId);
      if (!config) {
        throw new HttpError(404, 'TwoFactorNotSetup', {
          message: '2FA não foi configurado. Execute /setup primeiro.',
        });
      }

      if (config.enabled) {
        throw new HttpError(400, 'TwoFactorAlreadyEnabled');
      }

      // Check if locked
      const isLocked = await TwoFactorAuthModel.isLocked(userId);
      if (isLocked) {
        throw new HttpError(423, 'TwoFactorLocked', {
          message: '2FA está temporariamente bloqueado devido a múltiplas tentativas falhas',
        });
      }

      // Verify code
      const isValid = TotpService.verifyToken(value.code, config.secret);
      if (!isValid) {
        const failure = await TwoFactorAuthModel.recordFailure(userId);

        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'ENABLE_FAILED',
          method: 'TOTP',
          context: JSON.stringify({ code: value.code }),
          ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
          userAgent: req.headers['user-agent'] || null,
          success: false,
          failureReason: 'Invalid code',
        });

        if (failure.locked) {
          throw new HttpError(423, 'TwoFactorLocked', {
            message: 'Muitas tentativas falhas. 2FA bloqueado temporariamente.',
          });
        }

        throw new HttpError(400, 'InvalidCode', {
          message: 'Código inválido',
          attemptsRemaining: 3 - failure.attempts,
        });
      }

      // Generate recovery codes
      const recoveryCodes = TotpService.generateRecoveryCodes(10);
      await TwoFactorAuthModel.saveRecoveryCodes(userId, recoveryCodes);

      // Enable 2FA
      await TwoFactorAuthModel.enable(userId);
      await TwoFactorAuthModel.recordSuccess(userId);

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'ENABLED',
        method: 'TOTP',
        ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
        userAgent: req.headers['user-agent'] || null,
        success: true,
      });

      return res.json({
        ok: true,
        enabled: true,
        recoveryCodes, // Return plain codes only once
      });
    } catch (err) {
      return next(err);
    }
  }

  /**
   * Disable 2FA
   * POST /api/2fa/disable
   */
  async disable(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId;
      if (!userId) {
        throw new HttpError(401, 'Unauthorized');
      }

      const config = await TwoFactorAuthModel.findByUserId(userId);
      if (!config || !config.enabled) {
        throw new HttpError(400, 'TwoFactorNotEnabled', {
          message: '2FA não está ativado',
        });
      }

      // Verify code before disabling
      const { value, error } = verifySchema.validate(req.body);
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details });
      }

      let isValid = false;

      if (value.recoveryCode) {
        isValid = await TwoFactorAuthModel.verifyRecoveryCode(userId, value.recoveryCode);
      } else if (value.code) {
        isValid = TotpService.verifyToken(value.code, config.secret);
      }

      if (!isValid) {
        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'DISABLE_FAILED',
          method: 'TOTP',
          ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
          userAgent: req.headers['user-agent'] || null,
          success: false,
          failureReason: 'Invalid code',
        });
        throw new HttpError(400, 'InvalidCode', { message: 'Código inválido' });
      }

      await TwoFactorAuthModel.disable(userId);

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'DISABLED',
        method: 'TOTP',
        ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
        userAgent: req.headers['user-agent'] || null,
        success: true,
      });

      return res.json({
        ok: true,
        disabled: true,
      });
    } catch (err) {
      return next(err);
    }
  }

  /**
   * Get 2FA status
   * GET /api/2fa/status
   */
  async status(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId;
      if (!userId) {
        throw new HttpError(401, 'Unauthorized');
      }

      const config = await TwoFactorAuthModel.findByUserId(userId);
      const recoveryCodesCount = config?.enabled
        ? await TwoFactorAuthModel.getRecoveryCodesCount(userId)
        : 0;

      return res.json({
        ok: true,
        enabled: config?.enabled || false,
        verified: config?.verified || false,
        method: config?.method || null,
        recoveryCodesCount,
      });
    } catch (err) {
      return next(err);
    }
  }

  /**
   * Generate new recovery codes
   * POST /api/2fa/recovery-codes
   */
  async generateRecoveryCodes(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId;
      if (!userId) {
        throw new HttpError(401, 'Unauthorized');
      }

      const config = await TwoFactorAuthModel.findByUserId(userId);
      if (!config || !config.enabled) {
        throw new HttpError(400, 'TwoFactorNotEnabled', {
          message: '2FA não está ativado',
        });
      }

      // Verify code before generating new recovery codes
      const { value, error } = verifySchema.validate(req.body);
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details });
      }

      let isValid = false;

      if (value.recoveryCode) {
        isValid = await TwoFactorAuthModel.verifyRecoveryCode(userId, value.recoveryCode);
      } else if (value.code) {
        isValid = TotpService.verifyToken(value.code, config.secret);
      }

      if (!isValid) {
        throw new HttpError(400, 'InvalidCode', { message: 'Código inválido' });
      }

      // Generate new recovery codes
      const recoveryCodes = TotpService.generateRecoveryCodes(10);
      await TwoFactorAuthModel.saveRecoveryCodes(userId, recoveryCodes);

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'RECOVERY_CODES_REGENERATED',
        method: 'TOTP',
        ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
        userAgent: req.headers['user-agent'] || null,
        success: true,
      });

      return res.json({
        ok: true,
        recoveryCodes, // Return plain codes only once
      });
    } catch (err) {
      return next(err);
    }
  }

  /**
   * Verify 2FA code (for use in other flows)
   * POST /api/2fa/verify
   */
  async verify(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId;
      if (!userId) {
        throw new HttpError(401, 'Unauthorized');
      }

      const { value, error } = verifySchema.validate(req.body);
      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details });
      }

      const config = await TwoFactorAuthModel.findByUserId(userId);
      if (!config || !config.enabled) {
        throw new HttpError(400, 'TwoFactorNotEnabled', {
          message: '2FA não está ativado',
        });
      }

      // Check if locked
      const isLocked = await TwoFactorAuthModel.isLocked(userId);
      if (isLocked) {
        throw new HttpError(423, 'TwoFactorLocked', {
          message: '2FA está temporariamente bloqueado',
        });
      }

      let isValid = false;

      if (value.recoveryCode) {
        isValid = await TwoFactorAuthModel.verifyRecoveryCode(userId, value.recoveryCode);
      } else if (value.code) {
        isValid = TotpService.verifyToken(value.code, config.secret);
      }

      if (!isValid) {
        const failure = await TwoFactorAuthModel.recordFailure(userId);

        await TwoFactorAuthModel.addAuditLog({
          userId,
          action: 'VERIFY_FAILED',
          method: 'TOTP',
          context: JSON.stringify({
            code: value.code ? 'TOTP' : 'RECOVERY',
            hasRecoveryCode: !!value.recoveryCode,
          }),
          ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
          userAgent: req.headers['user-agent'] || null,
          success: false,
          failureReason: 'Invalid code',
        });

        if (failure.locked) {
          throw new HttpError(423, 'TwoFactorLocked', {
            message: 'Muitas tentativas falhas. 2FA bloqueado temporariamente.',
          });
        }

        throw new HttpError(400, 'InvalidCode', {
          message: 'Código inválido',
          attemptsRemaining: 3 - failure.attempts,
        });
      }

      await TwoFactorAuthModel.recordSuccess(userId);

      await TwoFactorAuthModel.addAuditLog({
        userId,
        action: 'VERIFY_SUCCESS',
        method: 'TOTP',
        context: JSON.stringify({
          code: value.code ? 'TOTP' : 'RECOVERY',
          hasRecoveryCode: !!value.recoveryCode,
        }),
        ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
        userAgent: req.headers['user-agent'] || null,
        success: true,
      });

      return res.json({
        ok: true,
        verified: true,
      });
    } catch (err) {
      return next(err);
    }
  }

  /**
   * Get audit logs
   * GET /api/2fa/audit-logs
   */
  async getAuditLogs(req, res, next) {
    try {
      const userId = req.user?.id || req.user?.userId;
      if (!userId) {
        throw new HttpError(401, 'Unauthorized');
      }

      const limit = parseInt(req.query.limit || 50, 10);
      const logs = await TwoFactorAuthModel.getAuditLogs(userId, limit);

      return res.json({
        ok: true,
        logs,
      });
    } catch (err) {
      return next(err);
    }
  }
}

export const twoFactorAuthController = new TwoFactorAuthController();
