import { Pool } from 'pg';
import { env } from './env.js';
export const pool = new Pool({
    connectionString: env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});
export async function initDb() {
    console.log('[DB auth-service] init...');
    await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      external_id TEXT,
      name TEXT NOT NULL,
      email TEXT,
      document TEXT,
      cnpj TEXT,
      company_name TEXT,
      trade_name TEXT,
      partner_name TEXT,
      cnpj_data JSONB,
      password_hash TEXT,
      role TEXT DEFAULT 'USER',
      doc_status TEXT DEFAULT 'PENDING',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
    await pool.query(`
    CREATE TABLE IF NOT EXISTS user_two_factor_auth (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      method TEXT NOT NULL DEFAULT 'TOTP',
      secret TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT FALSE,
      verified BOOLEAN NOT NULL DEFAULT FALSE,
      last_used_at TIMESTAMPTZ,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, method)
    );
  `);
    await pool.query(`
    CREATE TABLE IF NOT EXISTS user_recovery_codes (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
    await pool.query(`
    CREATE TABLE IF NOT EXISTS two_factor_audit_log (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      method TEXT NOT NULL,
      context TEXT,
      ip_address TEXT,
      user_agent TEXT,
      success BOOLEAN NOT NULL DEFAULT FALSE,
      failure_reason TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
    console.log('[DB auth-service] ok.');
}
