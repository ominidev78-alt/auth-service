import express from 'express';
import { maintenanceController } from '../controllers/MaintenanceController.js';
const router = express.Router();
/**
 * @openapi
 * /api/public/maintenance:
 *   get:
 *     summary: Retorna status de manutenção do sistema
 *     tags: [Public]
 *     responses:
 *       200:
 *         description: Status do sistema
 */
router.get('/maintenance', (req, res, next) => maintenanceController.publicStatus(req, res, next));
export default router;
