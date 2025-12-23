import express from 'express';

import authRoutes from './auth.routes.js';
import userAuthRoutes from './auth.user.routes.js';
import twoFactorAuthRoutes from './twoFactorAuth.routes.js';
import internalRoutes from './internal.routes.js';
import publicRoutes from './public.routes.js';
import adminMaintenanceRoutes from './admin.maintenance.routes.js';
import healthRoutes from './health.routes.js';

const router = express.Router();

router.use('/', healthRoutes);
router.use('/api', authRoutes);
router.use('/api', userAuthRoutes);
router.use('/api', twoFactorAuthRoutes);
router.use('/api', adminMaintenanceRoutes);
router.use('/api/internal', internalRoutes);
router.use('/api/public', publicRoutes);

export default router;
