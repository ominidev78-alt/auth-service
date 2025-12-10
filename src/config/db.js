import pkg from 'pg';
const { Pool } = pkg;
import { env } from './env.js';

export const db = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
