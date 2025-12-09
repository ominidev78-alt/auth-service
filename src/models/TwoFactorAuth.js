import { db } from '../config/db.js'

export const TwoFactorAuthModel = {
  getByUserId(id) {
    return db.query('SELECT * FROM user_two_factor_auth WHERE user_id = $1', [id])
  },
  enable(userId, secret) {
    return db.query(
      'INSERT INTO user_two_factor_auth (user_id, secret) VALUES ($1,$2) ON CONFLICT (user_id) DO UPDATE SET secret=$2 RETURNING *',
      [userId, secret]
    )
  },
  disable(userId) {
    return db.query('DELETE FROM user_two_factor_auth WHERE user_id=$1', [userId])
  }
}
