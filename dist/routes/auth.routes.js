import express from 'express';
import { authController } from '../controllers/AuthController.js';
import { userAuthController } from '../controllers/UserAuthController.js';
const router = express.Router();
router.post('/auth/token', (req, res, next) => authController.token(req, res, next));
router.post('/admin/auth/login', (req, res, next) => userAuthController.adminLogin(req, res, next));
router.post('/internal/operators/:id/generate-credentials', (req, res, next) => authController.generateCredentials(req, res, next));
export default router;
