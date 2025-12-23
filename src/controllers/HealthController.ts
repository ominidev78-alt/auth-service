import { Request, Response } from 'express'

export class HealthController {
  async health(req: Request, res: Response) {
    return res.json({ ok: true, service: "auth-service", timestamp: new Date().toISOString() })
  }
}
export const healthController = new HealthController()
