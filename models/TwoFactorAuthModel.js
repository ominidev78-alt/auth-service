import { pool } from '../config/db.js'
import { TotpService } from '../services/TotpService.js'

export class TwoFactorAuthModel {
  /**
   * Get 2FA configuration for user
   * @param {number} userId
   * @returns {Promise<Object|null>}
   */
  static async findByUserId(userId) {
    const { rows } = await pool.query(
      `
      SELECT *
      FROM user_two_factor_auth
      WHERE user_id = $1
      LIMIT 1;
      `,
      [userId]
    )
    return rows[0] || null
  }

  /**
   * Create or update 2FA configuration
   * @param {number} userId
   * @param {string} method - 'TOTP'
   * @param {string} secret
   * @param {boolean} enabled
   * @param {boolean} verified
   * @returns {Promise<Object>}
   */
  static async upsert({
    userId,
    method = 'TOTP',
    secret,
    enabled = false,
    verified = false
  }) {
    const { rows } = await pool.query(
      `
      INSERT INTO user_two_factor_auth (user_id, method, secret, enabled, verified)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (user_id, method)
      DO UPDATE SET
        secret = EXCLUDED.secret,
        enabled = EXCLUDED.enabled,
        verified = EXCLUDED.verified,
        updated_at = NOW()
      RETURNING *;
      `,
      [userId, method, secret, enabled, verified]
    )
    return rows[0]
  }

  /**
   * Enable 2FA for user
   * @param {number} userId
   * @returns {Promise<Object>}
   */
  static async enable(userId) {
    const { rows } = await pool.query(
      `
      UPDATE user_two_factor_auth
      SET
        enabled = TRUE,
        verified = TRUE,
        failed_attempts = 0,
        locked_until = NULL,
        last_used_at = NOW(),
        updated_at = NOW()
      WHERE user_id = $1
      RETURNING *;
      `,
      [userId]
    )
    return rows[0] || null
  }

  /**
   * Disable 2FA for user
   * @param {number} userId
   * @returns {Promise<Object>}
   */
  static async disable(userId) {
    const { rows } = await pool.query(
      `
      UPDATE user_two_factor_auth
      SET
        enabled = FALSE,
        verified = FALSE,
        updated_at = NOW()
      WHERE user_id = $1
      RETURNING *;
      `,
      [userId]
    )
    return rows[0] || null
  }

  /**
   * Record successful 2FA verification
   * @param {number} userId
   * @returns {Promise<void>}
   */
  static async recordSuccess(userId) {
    await pool.query(
      `
      UPDATE user_two_factor_auth
      SET
        last_used_at = NOW(),
        failed_attempts = 0,
        locked_until = NULL,
        updated_at = NOW()
      WHERE user_id = $1;
      `,
      [userId]
    )
  }

  /**
   * Record failed 2FA attempt
   * @param {number} userId
   * @param {number} maxAttempts - Maximum attempts before lock (default: 3)
   * @param {number} lockDurationMinutes - Lock duration in minutes (default: 15)
   * @returns {Promise<{locked: boolean, attempts: number}>}
   */
  static async recordFailure(userId, maxAttempts = 3, lockDurationMinutes = 15) {
    const { rows } = await pool.query(
      `
      UPDATE user_two_factor_auth
      SET
        failed_attempts = failed_attempts + 1,
        locked_until = CASE
          WHEN failed_attempts + 1 >= $2 THEN NOW() + INTERVAL '${lockDurationMinutes} minutes'
          ELSE locked_until
        END,
        updated_at = NOW()
      WHERE user_id = $1
      RETURNING failed_attempts, locked_until;
      `,
      [userId, maxAttempts]
    )

    const result = rows[0]
    const locked = result?.locked_until && new Date(result.locked_until) > new Date()

    return {
      locked,
      attempts: result?.failed_attempts || 0
    }
  }

  /**
   * Check if 2FA is locked
   * @param {number} userId
   * @returns {Promise<boolean>}
   */
  static async isLocked(userId) {
    const { rows } = await pool.query(
      `
      SELECT locked_until
      FROM user_two_factor_auth
      WHERE user_id = $1 AND enabled = TRUE;
      `,
      [userId]
    )

    if (!rows[0]) return false

    const lockedUntil = rows[0].locked_until
    if (!lockedUntil) return false

    return new Date(lockedUntil) > new Date()
  }

  /**
   * Save recovery codes (hashed)
   * @param {number} userId
   * @param {string[]} codes - Plain recovery codes
   * @returns {Promise<void>}
   */
  static async saveRecoveryCodes(userId, codes) {
    // Delete old unused codes
    await pool.query(
      `
      DELETE FROM user_recovery_codes
      WHERE user_id = $1 AND used = FALSE;
      `,
      [userId]
    )

    // Insert new codes using parameterized query
    for (const code of codes) {
      const hash = TotpService.hashRecoveryCode(code)
      await pool.query(
        `
        INSERT INTO user_recovery_codes (user_id, code_hash)
        VALUES ($1, $2);
        `,
        [userId, hash]
      )
    }
  }

  /**
   * Get unused recovery codes count
   * @param {number} userId
   * @returns {Promise<number>}
   */
  static async getRecoveryCodesCount(userId) {
    const { rows } = await pool.query(
      `
      SELECT COUNT(*) as count
      FROM user_recovery_codes
      WHERE user_id = $1 AND used = FALSE;
      `,
      [userId]
    )
    return parseInt(rows[0]?.count || 0, 10)
  }

  /**
   * Verify and consume recovery code
   * @param {number} userId
   * @param {string} code - Plain recovery code
   * @returns {Promise<boolean>} True if valid and consumed
   */
  static async verifyRecoveryCode(userId, code) {
    // Get all unused recovery codes for user
    const { rows } = await pool.query(
      `
      SELECT id, code_hash
      FROM user_recovery_codes
      WHERE user_id = $1 AND used = FALSE;
      `,
      [userId]
    )

    // Find matching code
    for (const row of rows) {
      if (TotpService.verifyRecoveryCode(code, row.code_hash)) {
        // Mark as used
        await pool.query(
          `
          UPDATE user_recovery_codes
          SET used = TRUE, used_at = NOW()
          WHERE id = $1;
          `,
          [row.id]
        )
        return true
      }
    }

    return false
  }

  /**
   * Add audit log entry
   * @param {Object} params
   * @returns {Promise<Object>}
   */
  static async addAuditLog({
    userId,
    action,
    method,
    context = null,
    ipAddress = null,
    userAgent = null,
    success = false,
    failureReason = null
  }) {
    const { rows } = await pool.query(
      `
      INSERT INTO two_factor_audit_log (
        user_id, action, method, context, ip_address, user_agent, success, failure_reason
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
      `,
      [userId, action, method, context, ipAddress, userAgent, success, failureReason]
    )
    return rows[0]
  }

  /**
   * Get audit logs for user
   * @param {number} userId
   * @param {number} limit
   * @returns {Promise<Array>}
   */
  static async getAuditLogs(userId, limit = 50) {
    const { rows } = await pool.query(
      `
      SELECT *
      FROM two_factor_audit_log
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2;
      `,
      [userId, limit]
    )
    return rows
  }
}

