import { Router } from 'express'
import { authController } from '../controllers/AuthController.js'

const router = Router()

router.post('/auth/login', (req,res,next)=>authController.login(req,res,next))
router.post('/auth/register', (req,res,next)=>authController.register(req,res,next))

export default router
