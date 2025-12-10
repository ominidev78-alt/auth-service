import dotenv from 'dotenv';
dotenv.config();

export const env = {
  PORT: process.env.PORT || 3001,
  DATABASE_URL: process.env.DATABASE_URL,
  JWT_USER_SECRET: process.env.JWT_USER_SECRET,
  JWT_OPERATOR_SECRET: process.env.JWT_OPERATOR_SECRET,
  JWT_ADMIN_SECRET: process.env.JWT_ADMIN_SECRET,
  NODE_ENV: process.env.NODE_ENV,
};
