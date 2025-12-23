import express from 'express'
import { authController } from '../controllers/AuthController.js'
import { userAuthController } from '../controllers/UserAuthController.js'

const router = express.Router()

/**
 * @openapi
 * tags:
 *   name: Auth
 *   description: Autenticação de operadores e administradores
 */

/**
 * @openapi
 * /api/auth/token:
 *   post:
 *     summary: Gera um access token JWT para o operador usando appId/appSecret
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/TokenRequest'
 *     responses:
 *       200:
 *         description: Token gerado com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenResponse'
 *       400:
 *         $ref: '#/components/responses/BadRequest'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */
router.post('/auth/token', (req, res, next) =>
  authController.token(req, res, next)
)

/**
 * @openapi
 * /api/admin/auth/login:
 *   post:
 *     summary: Login do administrador
 *     tags:
 *       - Auth
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: admin@pagandu.com
 *               password:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: Login admin realizado com sucesso
 *       401:
 *         description: Credenciais inválidas
 *       403:
 *         description: Acesso negado (não é ADMIN)
 */
router.post('/admin/auth/login', (req, res, next) =>
  userAuthController.adminLogin(req, res, next)
)

/**
 * @openapi
 * /auth/login:
 *   post:
 *     summary: Login de usuário com e-mail e senha
 *     tags:
 *       - UserAuth
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserLoginRequest'
 */
router.post('/internal/operators/:id/generate-credentials', (req, res, next) =>
  authController.generateCredentials(req, res, next)
)

export default router
