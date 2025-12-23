import express from 'express';

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
router.get('/maintenance', (req, res) => {
  // Por enquanto retorna que não está em manutenção
  // Futuramente pode checar Redis ou DB
  return res.json({
    data: {
      isActive: false,
      message: 'Sistema operacional'
    }
  });
});

export default router;
