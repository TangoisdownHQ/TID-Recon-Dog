// src/services/httpService.ts
import express, { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { logInteraction } from '../utils/logger.js';
import { config } from '../config/config.js';

const app = express();
app.set('trust proxy', 1); 
app.use(express.json());

// Middleware to extract and log real IP
app.use(async (req: Request, res: Response, next: NextFunction) => {
  let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  // If 'x-forwarded-for' has multiple IPs, take the first one
  if (typeof ip === 'string' && ip.includes(',')) {
    ip = ip.split(',')[0].trim();
  }

  const userAgent = req.headers['user-agent'] || 'unknown';
  const referrer = req.headers['referer'] || 'none';

  // Log real IP interactions
  await logInteraction('HTTP', ip as string, `Path: ${req.path}, User-Agent: ${userAgent}, Referrer: ${referrer}`);

  next();
});

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  keyGenerator: (req) => req.ip || '127.0.0.1', //Ensure req.ip is always used
  handler: (req, res) => {
    logInteraction('HTTP', req.ip || '127.0.0.1', 'Rate limit exceeded');
    res.status(429).send('Too many requests, please try again later.');
  }
});

app.use(generalLimiter);

// Example Route
app.get('/api/v1/users', (req: Request, res: Response) => {
  res.status(200).send({ message: 'User route accessed' });
});

// Start the HTTP server
app.listen(config.services.http.port, config.services.http.host, () => {
  console.log(`HTTP service running on ${config.services.http.host}:${config.services.http.port}`);
});

