import { Router } from 'express';
import { authController } from '../controllers/AuthController.js';

const router = Router();

router.post('/auth/login', (req, res, next) => authController.login(req, res, next));
router.post('/auth/register', (req, res, next) => authController.register(req, res, next));
router.post('/auth/forgot/start', (req, res, next) => authController.forgotStart(req, res, next));
router.post('/auth/forgot/verify', (req, res, next) => authController.forgotVerify(req, res, next));
router.post('/auth/forgot/reset', (req, res, next) => authController.forgotReset(req, res, next));

export default router;
