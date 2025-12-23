import express from 'express';
import { userAuthController } from '../controllers/UserAuthController.js';
import { userAuth } from '../middlewares/userAuth.js';
const router = express.Router();
/**
 * @openapi
 * /auth/register:
 *   post:
 *     summary: Cadastro de usuário (PF ou PJ) com e-mail e senha
 *     tags:
 *       - UserAuth
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserRegisterRequest'
 *     responses:
 *       201:
 *         description: Usuário registrado com sucesso e JWT retornado.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserAuthResponse'
 *       400:
 *         description: Payload inválido ou erro de validação.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       409:
 *         description: E-mail já cadastrado.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Erro interno inesperado.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post('/auth/register', (req, res, next) => userAuthController.register(req, res, next));
/**
 * @openapi
 * /auth/login:
 *   post:
 *     summary: Login de usuário com e-mail e senha
 *     tags:
 *       - UserAuth
 *     requestBody:
 *       required: true:
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserLoginRequest'
 *     responses:
 *       200:
 *         description: Login efetuado com sucesso e JWT retornado.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserAuthResponse'
 *       400:
 *         description: Payload inválido ou erro de validação.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Credenciais inválidas ou usuário bloqueado.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Erro interno inesperado.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post('/auth/login', (req, res, next) => userAuthController.login(req, res, next));
/**
 * @openapi
 * /auth/change-password:
 *   post:
 *     summary: Altera a senha do usuário (requer 2FA se ativado)
 *     tags:
 *       - UserAuth
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 description: Senha atual
 *               newPassword:
 *                 type: string
 *                 description: Nova senha (mínimo 6 caracteres)
 *               code:
 *                 type: string
 *                 description: Código 2FA de 6 dígitos (obrigatório se 2FA estiver ativado)
 *               recoveryCode:
 *                 type: string
 *                 description: Código de recuperação (alternativa ao código 2FA)
 *     responses:
 *       200:
 *         description: Senha alterada com sucesso
 *       400:
 *         description: Payload inválido ou código 2FA inválido
 *       401:
 *         description: Não autenticado ou senha atual incorreta
 *       423:
 *         description: 2FA bloqueado temporariamente
 */
router.post('/auth/change-password', userAuth, (req, res, next) => userAuthController.changePassword(req, res, next));
// Public forgot-password (pre-login) using email + 2FA
router.post('/auth/forgot/start', (req, res, next) => userAuthController.forgotStart(req, res, next));
router.post('/auth/forgot/verify', (req, res, next) => userAuthController.forgotVerify(req, res, next));
router.post('/auth/forgot/reset', (req, res, next) => userAuthController.forgotReset(req, res, next));
export default router;
