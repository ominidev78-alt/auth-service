import { Router } from 'express'
import { maintenanceController } from '../controllers/MaintenanceController.js'
import { adminAuth } from '../middlewares/adminAuth.js'

const router = Router()

/**
 * @openapi
 * tags:
 *   name: AdminMaintenance
 *   description: Configurações de modo manutenção do sistema.
 */

/**
 * @openapi
 * /api/admin/settings/maintenance:
 *   get:
 *     summary: Consulta status atual do modo manutenção
 *     tags: [AdminMaintenance]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Status atual do modo manutenção.
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */
router.get(
  '/admin/settings/maintenance',
  adminAuth,
  (req, res, next) => maintenanceController.adminGetStatus(req, res, next)
)

/**
 * @openapi
 * /api/admin/settings/maintenance:
 *   patch:
 *     summary: Ativa ou desativa o modo manutenção
 *     tags: [AdminMaintenance]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - isActive
 *             properties:
 *               isActive:
 *                 type: boolean
 *                 description: Flag de ativação do modo manutenção.
 *               message:
 *                 type: string
 *                 description: Mensagem opcional exibida para o usuário final.
 *     responses:
 *       200:
 *         description: Modo manutenção atualizado com sucesso.
 *       400:
 *         $ref: '#/components/responses/BadRequest'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */
router.patch(
  '/admin/settings/maintenance',
  adminAuth,
  (req, res, next) => maintenanceController.adminToggle(req, res, next)
)

export default router
