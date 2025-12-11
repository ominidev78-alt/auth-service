import Joi from 'joi'
import { MaintenanceModeModel } from '../models/MaintenanceModeModel.js'
import { HttpError } from '../core/HttpError.js'

const toggleSchema = Joi.object({
  isActive: Joi.boolean().required(),
  message: Joi.string().allow('', null)
})

class MaintenanceController {
  async adminGetStatus(req, res, next) {
    try {
      const data = await MaintenanceModeModel.get()

      return res.json({
        ok: true,
        data: {
          isActive: Boolean(data.is_active),
          message: data.message || null,
          updatedAt: data.updated_at
        }
      })
    } catch (err) {
      next(err)
    }
  }

  async adminToggle(req, res, next) {
    try {
      const { value, error } = toggleSchema.validate(req.body, {
        abortEarly: false
      })

      if (error) {
        throw new HttpError(400, 'ValidationError', { details: error.details })
      }

      const updated = await MaintenanceModeModel.setActive(
        value.isActive,
        value.message
      )

      return res.json({
        ok: true,
        data: {
          isActive: Boolean(updated.is_active),
          message: updated.message || null,
          updatedAt: updated.updated_at
        }
      })
    } catch (err) {
      next(err)
    }
  }

  async publicStatus(req, res, next) {
    try {
      const data = await MaintenanceModeModel.get()

      return res.json({
        ok: true,
        data: {
          isActive: Boolean(data.is_active),
          message: data.message || 'O sistema está em manutenção, tente novamente mais tarde.'
        }
      })
    } catch (err) {
      next(err)
    }
  }
}

export const maintenanceController = new MaintenanceController()
