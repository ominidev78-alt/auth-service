import { pool } from '../config/db.js';
import { TotpService } from '../services/TotpService.js';
export class TwoFactorAuthModel {
    static async findByUserId(userId) {
        const { rows } = await pool.query(`      SELECT *      FROM user_two_factor_auth      WHERE user_id = $1      LIMIT 1;      `, [userId]);
        return rows[0] || null;
    }
    static async upsert({ userId, method = 'TOTP', secret, enabled = false, verified = false }) {
        const { rows } = await pool.query(`      INSERT INTO user_two_factor_auth (user_id, method, secret, enabled, verified)      VALUES ($1, $2, $3, $4, $5)      ON CONFLICT (user_id, method)      DO UPDATE SET        secret = EXCLUDED.secret,        enabled = EXCLUDED.enabled,        verified = EXCLUDED.verified,        updated_at = NOW()      RETURNING *;      `, [userId, method, secret, enabled, verified]);
        return rows[0];
    }
    static async enable(userId) {
        const { rows } = await pool.query(`      UPDATE user_two_factor_auth      SET        enabled = TRUE,        verified = TRUE,        failed_attempts = 0,        locked_until = NULL,        last_used_at = NOW(),        updated_at = NOW()      WHERE user_id = $1      RETURNING *;      `, [userId]);
        return rows[0] || null;
    }
    static async disable(userId) {
        const { rows } = await pool.query(`      UPDATE user_two_factor_auth      SET        enabled = FALSE,        verified = FALSE,        updated_at = NOW()      WHERE user_id = $1      RETURNING *;      `, [userId]);
        return rows[0] || null;
    }
    static async recordSuccess(userId) {
        await pool.query(`      UPDATE user_two_factor_auth      SET        last_used_at = NOW(),        failed_attempts = 0,        locked_until = NULL,        updated_at = NOW()      WHERE user_id = $1;      `, [userId]);
    }
    static async recordFailure(userId, maxAttempts = 3, lockDurationMinutes = 15) {
        const { rows } = await pool.query(`      UPDATE user_two_factor_auth      SET        failed_attempts = failed_attempts + 1,        locked_until = NULL, -- DISABLED LOCKING: CASE WHEN failed_attempts + 1 >= $2 THEN NOW() + INTERVAL '${lockDurationMinutes} minutes' ELSE locked_until END,        updated_at = NOW()      WHERE user_id = $1      RETURNING failed_attempts, locked_until;      `, [userId]);
        const result = rows[0];
        const locked = !!(result?.locked_until && new Date(result.locked_until) > new Date());
        return {
            locked,
            attempts: result?.failed_attempts || 0
        };
    }
    static async isLocked(userId) {
        const { rows } = await pool.query(`      SELECT locked_until      FROM user_two_factor_auth      WHERE user_id = $1 AND enabled = TRUE;      `, [userId]);
        if (!rows[0])
            return false;
        const lockedUntil = rows[0].locked_until;
        if (!lockedUntil)
            return false;
        return false;
    }
    static async saveRecoveryCodes(userId, codes) {
        await pool.query(`      DELETE FROM user_recovery_codes      WHERE user_id = $1 AND used = FALSE;      `, [userId]);
        for (const code of codes) {
            const hash = TotpService.hashRecoveryCode(code);
            await pool.query(`        INSERT INTO user_recovery_codes (user_id, code_hash)        VALUES ($1, $2);        `, [userId, hash]);
        }
    }
    static async getRecoveryCodesCount(userId) {
        const { rows } = await pool.query(`      SELECT COUNT(*) as count      FROM user_recovery_codes      WHERE user_id = $1 AND used = FALSE;      `, [userId]);
        return parseInt(rows[0]?.count || 0, 10);
    }
    static async verifyRecoveryCode(userId, code) {
        const { rows } = await pool.query(`      SELECT id, code_hash      FROM user_recovery_codes      WHERE user_id = $1 AND used = FALSE;      `, [userId]);
        for (const row of rows) {
            if (TotpService.verifyRecoveryCode(code, row.code_hash)) {
                await pool.query(`          UPDATE user_recovery_codes          SET used = TRUE, used_at = NOW()          WHERE id = $1;          `, [row.id]);
                return true;
            }
        }
        return false;
    }
    static async addAuditLog({ userId, action, method, context = null, ipAddress = null, userAgent = null, success = false, failureReason = null }) {
        const { rows } = await pool.query(`      INSERT INTO two_factor_audit_log (        user_id, action, method, context, ip_address, user_agent, success, failure_reason      )      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)      RETURNING *;      `, [userId, action, method, context, ipAddress, userAgent, success, failureReason]);
        return rows[0];
    }
    static async getAuditLogs(userId, limit = 50) {
        const { rows } = await pool.query(`      SELECT *      FROM two_factor_audit_log      WHERE user_id = $1      ORDER BY created_at DESC      LIMIT $2;      `, [userId, limit]);
        return rows;
    }
}
