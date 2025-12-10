import Joi from 'joi';

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  code: Joi.string().length(6).pattern(/^\d+$/).optional(),
  recoveryCode: Joi.string().optional(),
});
