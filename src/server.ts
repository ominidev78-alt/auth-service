import { app } from './app.js';
import { env } from './config/env.js';
import { initDb } from './config/db.js';

async function start() {
  try {
    await initDb();

    const PORT: number = Number(env.PORT) || 3001;

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`auth-service rodando na porta ${PORT}`);
    });
  } catch (err) {
    console.error('Erro ao iniciar auth-service:', err);
    process.exit(1);
  }
}

start();
