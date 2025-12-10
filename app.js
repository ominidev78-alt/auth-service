import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import hpp from 'hpp';
import cors from 'cors';
import { notFoundHandler, globalErrorHandler } from './core/errorHandler.js';
import authRoutes from './routes/auth.routes.js';
import twoFactorAuthRoutes from './routes/twoFactorAuth.routes.js';

const app = express();

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));
app.use(helmet());
app.use(hpp());

app.use('/api', authRoutes);
app.use('/api', twoFactorAuthRoutes);

app.use(notFoundHandler);
app.use(globalErrorHandler);

export default app;
export { app };
