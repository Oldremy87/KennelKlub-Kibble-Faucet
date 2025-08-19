require('dotenv').config();
const express = require('express');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const helmet = require('helmet');
const validator = require('validator');
const winston = require('winston');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { Address, Networks } = require('libnexa-ts');
const hcaptcha = require('hcaptcha');
const app = express();

// Setup logging with winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'faucet.log' })
  ]
});

app.use(express.json());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      scriptSrcAttr: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "https://42ee4d0b0e71.ngrok-free.app", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      frameSrc: ["'self'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
app.use((req, res, next) => {
  logger.info('Incoming request:', { method: req.method, url: req.url, ip: req.ip, timestamp: new Date().toISOString() });
  next();
});

app.use(express.static('public', {
  setHeaders: (res, path) => {
    if (path.endsWith('.js')) {
      res.set('Content-Type', 'application/javascript');
    } else if (path.endsWith('.svg')) {
      res.set('Content-Type', 'image/svg+xml');
    } else if (path.endsWith('.ico')) {
      res.set('Content-Type', 'image/x-icon');
    }
  }
}));

// Apply ipLimiter only to POST /request-kibl
const ipLimiter = rateLimit({
  windowMs: 2 * 60 * 60 * 1000, // 2 hours
  max: 2, // Allow 2 POST requests per IP
  message: { error: 'IP rate limit exceeded. Try again in 2 hours.' },
  keyGenerator: (req) => {
    return req.method === 'POST' && req.path === '/request-kibl' ? ipKeyGenerator(req) + (req.headers['user-agent'] || '') : null;
  },
  skip: (req) => req.method !== 'POST' || req.path !== '/request-kibl' // Skip non-POST or non-/request-kibl
});

const addressRateLimit = new Map();
const ipAddressLimit = new Map();

// Enhanced cleanup function
function cleanupExpiredLimits() {
  const now = Date.now();
  const twoHoursMs = 2 * 60 * 60 * 1000;
  const initialCount = { address: addressRateLimit.size, ip: ipAddressLimit.size };
  let cleaned = { address: 0, ip: 0 };
  for (let [key, timestamp] of addressRateLimit) {
    if (now - timestamp >= twoHoursMs) {
      addressRateLimit.delete(key);
      cleaned.address++;
    }
  }
  for (let [key, timestamp] of ipAddressLimit) {
    if (now - timestamp >= twoHoursMs) {
      ipAddressLimit.delete(key);
      cleaned.ip++;
    }
  }
  logger.info('Cleaned expired limits:', { now, initialCount, cleaned, remaining: { address: addressRateLimit.size, ip: ipAddressLimit.size } });
}

// Run cleanup periodically
setInterval(cleanupExpiredLimits, 5 * 60 * 1000); // Every 5 minutes

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.post('/request-kibl', ipLimiter, async (req, res, next) => {
  logger.info('POST /request-kibl received at:', { timestamp: new Date().toISOString(), rawBody: req.body });
  const { address, 'h-captcha-response': captchaToken } = req.body;
  logger.info('hCaptcha token received:', { captchaToken });
  if (!captchaToken) {
    logger.warn('Missing hCaptcha token');
    return res.status(400).json({ error: 'Please complete the hCaptcha challenge!' });
  }

  let captchaResponse;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      captchaResponse = await hcaptcha.verify(process.env.HCAPTCHA_SECRET, captchaToken, { host: 'https://hcaptcha.com' });
      logger.info('hCaptcha verification response (attempt ' + attempt + '):', { success: captchaResponse.success, errorCodes: captchaResponse['error-codes'] });
      break;
    } catch (error) {
      logger.error('hCaptcha verification error (attempt ' + attempt + '):', { error });
      if (attempt === 3) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
  if (!captchaResponse.success) {
    logger.warn('hCaptcha verification failed after retries', { errorCodes: captchaResponse['error-codes'] });
    return res.status(400).json({ error: 'hCaptcha verification failed! Error: ' + (captchaResponse['error-codes'] || 'Unknown') });
  }
  next();
}, async (req, res) => {
  cleanupExpiredLimits(); // Call cleanup before checks
  const { address } = req.body;
  logger.info('Processing raw address:', { address });
  const sanitizedAddress = validator.trim(address);
  logger.info('Sanitized address:', { sanitizedAddress });
  if (!sanitizedAddress) {
    logger.warn('Address is empty:', { sanitizedAddress });
    return res.status(400).json({ error: 'Address cannot be empty!' });
  }
  if (!Address.isValid(sanitizedAddress, Networks.mainnet)) {
    logger.warn('Address validation failed:', { sanitizedAddress });
    return res.status(400).json({ error: 'Invalid Nexa mainnet address! Please check your address and try again.' });
  }

  const now = Date.now();
  const ipAddressKey = `${req.ip}:${sanitizedAddress}`;
  if (ipAddressLimit.has(ipAddressKey) && (now - ipAddressLimit.get(ipAddressKey)) < twoHoursMs) {
    logger.warn('IP and address combination rate limit exceeded:', { ipAddressKey, timeRemaining: (twoHoursMs - (now - ipAddressLimit.get(ipAddressKey))) / (60 * 1000) });
    return res.status(429).json({ error: 'IP and address combination rate limit exceeded. Try again in ' + Math.ceil((twoHoursMs - (now - ipAddressLimit.get(ipAddressKey))) / (60 * 1000)) + ' minutes.' });
  }
  if (addressRateLimit.has(sanitizedAddress) && (now - addressRateLimit.get(sanitizedAddress)) < twoHoursMs) {
    logger.warn('Address rate limit exceeded:', { sanitizedAddress, timeRemaining: (twoHoursMs - (now - addressRateLimit.get(sanitizedAddress))) / (60 * 1000) });
    return res.status(429).json({ error: 'Address rate limit exceeded. Try again in ' + Math.ceil((twoHoursMs - (now - addressRateLimit.get(sanitizedAddress))) / (60 * 1000)) + ' minutes.' });
  }

  try {
    const rpcUrl = process.env.RPC_URL ? process.env.RPC_URL : `http://localhost:${process.env.RPC_PORT || 7227}`;
    logger.info('RPC URL:', { rpcUrl });
    const auth = Buffer.from(`${process.env.RPC_USER}:${process.env.RPC_PASSWORD}`).toString('base64');
    const body = JSON.stringify({
      jsonrpc: "1.0",
      id: "curltest",
      method: "token",
      params: ["send", process.env.KIBL_GROUP_ID, sanitizedAddress, 2500000] // 25,000 KIBL in satoshis
    });
    logger.info('RPC request body:', { body });

    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const response = await fetch(rpcUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'text/plain',
            'Authorization': `Basic ${auth}`
          },
          body
        });
        logger.info('Fetch response status:', { status: response.status });
        const data = await response.json();
        logger.info('RPC response:', { data });
        if (data.error) {
          throw new Error(data.error.message || 'Unknown RPC error');
        }
        const txId = data.result;
        const successResponse = {
          success: true,
          txId: txId,
          message: `Sent 25,000 KIBL to ${sanitizedAddress}`
        };
        logger.info('Success response:', { response: successResponse });
        addressRateLimit.set(sanitizedAddress, now);
        ipAddressLimit.set(ipAddressKey, now);
        return res.json(successResponse);
      } catch (error) {
        logger.error(`Attempt ${attempt} failed at ${new Date().toISOString()}:`, { error });
        if (attempt === 3) throw error;
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  } catch (error) {
    logger.error('Token send failed at:', { timestamp: new Date().toISOString(), error });
    res.status(500).json({ error: 'Failed to send tokens due to a server issue. Please try again later or contact support.' });
  }
});

app.listen(3000, () => console.log('Server running at http://localhost:3000', new Date().toISOString()));