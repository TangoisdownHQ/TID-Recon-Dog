var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
// src/services/httpService.ts
import express from 'express';
import rateLimit from 'express-rate-limit';
import { logInteraction } from '../utils/logger.js';
import { config } from '../config/config.js';
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
// Middleware to extract and log real IP
app.use((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    // If 'x-forwarded-for' has multiple IPs, take the first one
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }
    const userAgent = req.headers['user-agent'] || 'unknown';
    const referrer = req.headers['referer'] || 'none';
    // Log real IP interactions
    yield logInteraction('HTTP', ip, `Path: ${req.path}, User-Agent: ${userAgent}, Referrer: ${referrer}`);
    next();
}));
// Rate limiting
const generalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100,
    keyGenerator: (req) => req.ip || '127.0.0.1',
    handler: (req, res) => {
        logInteraction('HTTP', req.ip || '127.0.0.1', 'Rate limit exceeded');
        res.status(429).send('Too many requests, please try again later.');
    }
});
app.use(generalLimiter);
// Example Route
app.get('/api/v1/users', (req, res) => {
    res.status(200).send({ message: 'User route accessed' });
});
// Start the HTTP server
app.listen(config.services.http.port, config.services.http.host, () => {
    console.log(`HTTP service running on ${config.services.http.host}:${config.services.http.port}`);
});
