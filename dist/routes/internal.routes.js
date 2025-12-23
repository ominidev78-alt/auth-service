import express from 'express';
import { authController } from '../controllers/AuthController.js';
const router = express.Router();
/**
 * @openapi
 * tags:
 *   name: Internal
 *   description: Rotas internas usadas apenas pelo API Gateway / sistemas da casa.
 */
/**
 * @openapi
 * /api/internal/users/{id}/generate-credentials:
 *   post:
 *     summary: Gera novas credenciais (app_id e client_secret) para o usuário
 *     tags: [Internal]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Credenciais geradas com sucesso.
 *       404:
 *         description: Usuário não encontrado.
 *       500:
 *         description: Erro interno.
 */
router.post('/users/:id/generate-credentials', (req, res, next) => authController.generateCredentials(req, res, next));
export default router;
