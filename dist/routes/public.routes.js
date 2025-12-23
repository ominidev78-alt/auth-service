import express from 'express';
import { maintenanceController } from '../controllers/MaintenanceController.js';
const router = express.Router();
router.get('/maintenance', (req, res, next) => maintenanceController.publicStatus(req, res, next));
export default router;
