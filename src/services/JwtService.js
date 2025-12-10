import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

export const JwtService = {
  signUser(user) {
    return jwt.sign({ id: user.id, role: 'USER' }, env.JWT_USER_SECRET, { expiresIn: '7d' });
  },
  verifyUser(token) {
    return jwt.verify(token, env.JWT_USER_SECRET);
  },
  signAdmin(admin) {
    return jwt.sign({ id: admin.id, role: 'ADMIN' }, env.JWT_ADMIN_SECRET, { expiresIn: '1d' });
  },
};
