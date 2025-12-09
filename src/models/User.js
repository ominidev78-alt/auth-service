import { db } from '../config/db.js'

export const UserModel = {
  findByEmail(email) {
    return db.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email])
  },
  findById(id) {
    return db.query('SELECT * FROM users WHERE id = $1', [id])
  },
  create(email, passwordHash) {
    return db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1,$2) RETURNING *',
      [email, passwordHash]
    )
  }
}
