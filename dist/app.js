import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import hpp from 'hpp';
import cors from 'cors';
import compression from 'compression';
import { v4 as uuid } from 'uuid';
import http from 'http';
import https from 'https';
import axios from 'axios';
import routes from './routes/index.js';
import { notFoundHandler, globalErrorHandler } from './core/errorHandler.js';
import { swaggerSpec, getSwaggerHtml } from './swagger/swagger.js';
import { userAuthController } from './controllers/UserAuthController.js';
import { env } from './config/env.js';
const app = express();
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:5173',
    'https://pagandu.com',
    'https://www.pagandu.com',
    'https://api.pagandu.com',
    'https://admin.pagandu.com',
    'https://payg2a.online',
    'https://omnigateway.site',
    'https://admin.omnigateway.site'
];
app.use(cors({
    origin(origin, callback) {
        if (!origin)
            return callback(null, true);
        const normalizedOrigin = origin.replace(/\/$/, '');
        const isAllowed = allowedOrigins.some(o => normalizedOrigin === o.replace(/\/$/, ''));
        if (isAllowed)
            callback(null, true);
        else
            callback(new Error(`CORS bloqueado: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'app_id',
        'app_secret',
        'client_id',
        'client_secret',
        'x-api-key',
        'x-user-id',
        'x-app-id',
        'Accept',
        'Origin',
        'X-Requested-With'
    ],
    exposedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 204
}));
if (env.NODE_ENV !== 'production') {
    app.use(morgan('dev'));
}
else {
    app.use(morgan('combined'));
}
app.use(helmet());
app.use(hpp());
app.use(express.json({ limit: '2mb', type: ['application/json', 'application/*+json'] }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(compression());
app.use((req, res, next) => {
    req.id = req.headers['x-request-id'] || uuid();
    res.setHeader('X-Request-Id', req.id);
    next();
});
const httpAgent = new http.Agent({ keepAlive: true });
const httpsAgent = new https.Agent({ keepAlive: true });
export const httpClient = axios.create({
    timeout: 15000,
    httpAgent,
    httpsAgent
});
export const userService = axios.create({
    baseURL: env.USER_SERVICE_URL,
    timeout: 15000,
    httpAgent,
    httpsAgent
});
if (env.ENABLE_SWAGGER === 'true' || env.NODE_ENV !== 'production') {
    app.get('/docs-json', (req, res) => res.json(swaggerSpec));
    app.get('/docs', (req, res) => {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(getSwaggerHtml());
    });
}
// Direto para Auth (facilitar integrações core)
app.post('/api/auth/login', (req, res, next) => userAuthController.login(req, res, next));
app.post('/api/auth/register', (req, res, next) => userAuthController.register(req, res, next));
app.use(routes);
app.use(notFoundHandler);
app.use(globalErrorHandler);
export { app };
export default app;
