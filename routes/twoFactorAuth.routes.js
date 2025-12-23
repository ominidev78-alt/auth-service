import { Router } from 'express';
import { twoFactorAuthController } from '../controllers/TwoFactorAuthController.js';
import { userAuth } from '../middlewares/userAuth.js';

const router = Router();

/**
 * @openapi
 * tags:
 *   name: TwoFactorAuth
 *   description: Autenticação de dois fatores (2FA) usando TOTP
 */

/**
 * @openapi
 * /api/2fa/setup:
 *   post:
 *     summary: Inicia configuração de 2FA - gera secret e QR code
 *     tags: [TwoFactorAuth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Secret e QR code gerados com sucesso
 *       400:
 *         description: 2FA já está ativado
 *       401:
 *         description: Não autenticado
 */
router.post('/2fa/setup', userAuth, (req, res, next) =>
  twoFactorAuthController.setup(req, res, next)
);

/**
 * @openapi
 * /api/2fa/enable:
 *   post:
 *     summary: Ativa 2FA após verificação do código
 *     tags: [TwoFactorAuth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - code
 *             properties:
 *               code:
 *                 type: string
 *                 description: Código TOTP de 6 dígitos
 *     responses:
 *       200:
 *         description: 2FA ativado com sucesso
 *       400:
 *         description: Código inválido
 *       401:
 *         description: Não autenticado
 */
router.post('/2fa/enable', userAuth, (req, res, next) =>
  twoFactorAuthController.enable(req, res, next)
);

/**
 * @openapi
 * /api/2fa/disable:
 *   post:
 *     summary: Desativa 2FA
 *     tags: [TwoFactorAuth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               code:
 *                 type: string
 *                 description: Código TOTP de 6 dígitos
 *               recoveryCode:
 *                 type: string
 *                 description: Código de recuperação
 *     responses:
 *       200:
 *         description: 2FA desativado com sucesso
 *       400:
 *         description: Código inválido
 *       401:
 *         description: Não autenticado
 */
router.post('/2fa/disable', userAuth, (req, res, next) =>
  twoFactorAuthController.disable(req, res, next)
);

/**
 * @openapi
 * /api/2fa/status:
 *   get:
 *     summary: Obtém status do 2FA
 *     tags: [TwoFactorAuth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Status do 2FA
 *       401:
 *         description: Não autenticado
 */
router.get('/2fa/status', userAuth, (req, res, next) =>
  twoFactorAuthController.status(req, res, next)
);

/**
 * @openapi
 * /api/2fa/verify:
 *   post:
 *     summary: Verifica código 2FA
 *     tags: [TwoFactorAuth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               code:
 *                 type: string
 *                 description: Código TOTP de 6 dígitos
 *               recoveryCode:
 *                 type: string
 *                 description: Código de recuperação
 *     responses:
 *       200:
 *         description: Código verificado com sucesso
 *       400:
 *         description: Código inválido
 *       401:
 *         description: Não autenticado
 */
router.post('/2fa/verify', userAuth, (req, res, next) =>
  twoFactorAuthController.verify(req, res, next)
);

/**
 * @openapi
 * /api/2fa/recovery-codes:
 *   post:
 *     summary: Gera novos códigos de recuperação
 *     tags: [TwoFactorAuth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               code:
 *                 type: string
 *                 description: Código TOTP de 6 dígitos
 *               recoveryCode:
 *                 type: string
 *                 description: Código de recuperação
 *     responses:
 *       200:
 *         description: Novos códigos de recuperação gerados
 *       400:
 *         description: Código inválido
 *       401:
 *         description: Não autenticado
 */
router.post('/2fa/recovery-codes', userAuth, (req, res, next) =>
  twoFactorAuthController.regenerateRecoveryCodes(req, res, next)
);

/**
 * @openapi
 * /api/2fa/audit-logs:
 *   get:
 *     summary: Obtém logs de auditoria do 2FA
 *     tags: [TwoFactorAuth]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *     responses:
 *       200:
 *         description: Logs de auditoria
 *       401:
 *         description: Não autenticado
 */
router.get('/2fa/audit-logs', userAuth, (req, res, next) =>
  twoFactorAuthController.auditLogs(req, res, next)
);

export default router;
