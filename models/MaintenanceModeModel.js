import { pool } from '../config/db.js'

export class MaintenanceModeModel {
  static async get() {
    const { rows } = await pool.query(
      `
      SELECT id, is_active, message, created_at, updated_at
      FROM maintenance_mode
      WHERE id = 1
      LIMIT 1;
      `
    )

    if (!rows[0]) {
      const inserted = await pool.query(
        `
        INSERT INTO maintenance_mode (id, is_active)
        VALUES (1, false)
        ON CONFLICT (id) DO NOTHING
        RETURNING id, is_active, message, created_at, updated_at;
        `
      )
      return inserted.rows[0] || { id: 1, is_active: false, message: null }
    }

    return rows[0]
  }

  static async setActive(isActive, message = null) {
    const { rows } = await pool.query(
      `
      INSERT INTO maintenance_mode (id, is_active, message)
      VALUES (1, $1, $2)
      ON CONFLICT (id) DO UPDATE
        SET is_active = EXCLUDED.is_active,
            message   = EXCLUDED.message,
            updated_at = now()
      RETURNING id, is_active, message, created_at, updated_at;
      `,
      [Boolean(isActive), message || null]
    )

    return rows[0]
  }
}
