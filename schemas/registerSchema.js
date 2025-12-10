import Joi from 'joi'

export const registerSchema = Joi.object({
    personType: Joi.string().valid('PF', 'PJ').required(),
    name: Joi.string().min(2).when('personType', {
        is: 'PF',
        then: Joi.required(),
        otherwise: Joi.optional().allow('', null)
    }),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    document: Joi.string().when('personType', {
        is: 'PF',
        then: Joi.required(),
        otherwise: Joi.optional().allow(null, '')
    }),
    cnpj: Joi.string().when('personType', {
        is: 'PJ',
        then: Joi.required(),
        otherwise: Joi.optional().allow(null, '')
    }),
    companyName: Joi.string().when('personType', {
        is: 'PJ',
        then: Joi.required(),
        otherwise: Joi.optional().allow(null, '')
    }),
    tradeName: Joi.string().allow('', null),
    partnerName: Joi.string().allow('', null),
    externalId: Joi.string().allow('', null)
})