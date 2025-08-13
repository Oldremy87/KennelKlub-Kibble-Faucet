require('dotenv').config();
const express = require('express');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const helmet = require('helmet');
const validator = require('validator');
const winston = require('winston');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { Address, Networks } = require('libnexa-ts');
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
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "https://346d614067e1.ngrok-free.app"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));
app.use((req, res, next) => {
  logger.info('Incoming request:', { method: req.method, url: req.url, ip: req.ip, timestamp: new Date().toISOString() });
  next();
});
app.use(express.static('public'));

// Rate limiting (1 request per IP per 24 hours)
const ipLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: 1,
  message: { error: 'IP rate limit exceeded. Try again in 24 hours.' },
  keyGenerator: ipKeyGenerator
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

const addressRateLimit = new Map();
const ipAddressLimit = new Map(); // Track IP + address combinations

app.post('/request-kibl', ipLimiter, (req, res, next) => {
  logger.info('POST /request-kibl received at:', { timestamp: new Date().toISOString(), rawBody: req.body });
  next();
}, async (req, res) => {
  const { address } = req.body;
  logger.info('Processing raw address:', { address });
  const sanitizedAddress = validator.trim(address);
  logger.info('Sanitized address:', { sanitizedAddress });
  if (!sanitizedAddress) {
    logger.warn('Address is empty:', { sanitizedAddress });
    return res.status(400).json({ error: 'Address cannot be empty!' });
  }
  if (!Address.isValid(sanitizedAddress, Networks.testnet)) {
    logger.warn('Address validation failed:', { sanitizedAddress });
    return res.status(400).json({ error: 'Invalid Nexa testnet address! Please check your address and try again.' });
  }

  const now = Date.now();
  const ipAddressKey = `${req.ip}:${sanitizedAddress}`; // Unique key for IP + address
  if (ipAddressLimit.has(ipAddressKey) && (now - ipAddressLimit.get(ipAddressKey)) < 4 * 60 * 60 * 1000) {
    return res.status(429).json({ error: 'IP and address combination rate limit exceeded. Try again in 4 hours.' });
  }
  if (addressRateLimit.has(sanitizedAddress) && (now - addressRateLimit.get(sanitizedAddress)) < 24 * 60 * 60 * 1000) {
    return res.status(429).json({ error: 'Address rate limit exceeded. Try again in 24 hours.' });
  }

  try {
    const rpcUrl = process.env.RPC_URL ? process.env.RPC_URL : `http://localhost:${process.env.RPC_PORT || 7229}`;
    logger.info('RPC URL:', { rpcUrl });
    const auth = Buffer.from(`${process.env.RPC_USER}:${process.env.RPC_PASSWORD}`).toString('base64');
    const body = JSON.stringify({
      jsonrpc: "1.0",
      id: "curltest",
      method: "token",
      params: ["send", process.env.KIBL_GROUP_ID, sanitizedAddress, 1000 * Math.pow(10, 8)]
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
        addressRateLimit.set(sanitizedAddress, now);
        ipAddressLimit.set(ipAddressKey, now); // Update both limits
        return res.json({ success: true, txId, message: 'Sent 1000 KIBL to ' + sanitizedAddress });
      } catch (error) {
        logger.error(`Attempt ${attempt} failed at ${new Date().toISOString()}:`, { error });
        if (attempt === 3) throw error;
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  } catch (error) {
    logger.error('Token send failed at:', { timestamp: new Date().toISOString(), error });
    res.status(500).json({ error: 'Failed to send tokens. Try later or contact support.' });
  }
});

app.listen(3000, () => console.log('Server running at http://localhost:3000', new Date().toISOString()));