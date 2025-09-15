const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const winston = require('winston');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console()
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.File({ filename: 'combined.log' }));
}

// Tách lưu trữ IP và thiết bị
const ipBlocks = new Map(); // Map<IP, { timestamp: number, blocked: boolean, count: number }>
const deviceBlocks = new Map(); // Map<fingerprint, { timestamp: number, blocked: boolean, count: number }>
const csrfTokens = new Map(); // Map<IP, CSRF token>

app.use(express.json());
app.use(express.static('public', { etag: false, lastModified: false }));

app.get('/verify', (req, res) => {
    logger.info(`Serving /verify for IP: ${req.clientIp}`);
    res.sendFile('index.html', { root: __dirname + '/public' });
});

app.get('/', (req, res) => {
    logger.info(`Redirecting from / to /verify for IP: ${req.clientIp}`);
    res.redirect('/verify');
});

app.use((req, res, next) => {
    req.clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || req.connection.remoteAddress;
    req.clientDevice = req.headers['user-agent'] || 'unknown';
    req.clientFingerprint = req.body?.deviceInfo?.fingerprint || `${req.clientIp}-${req.clientDevice}-${req.headers['accept'] || ''}`.slice(0, 100);
    logger.info(`Request from IP: ${req.clientIp}, Device: ${req.clientDevice}, Fingerprint: ${req.clientFingerprint}, Path: ${req.path}`);
    next();
});

app.post('/get-csrf-token', (req, res) => {
    const ip = req.clientIp;
    const { deviceInfo, clientIp } = req.body;
    const fingerprint = deviceInfo?.fingerprint;
    const now = Date.now();

    let ipData = ipBlocks.get(ip) || { timestamp: now, blocked: false, count: 0 };
    let deviceData = deviceBlocks.get(fingerprint) || { timestamp: now, blocked: false, count: 0 };

    // Reset nếu quá thời gian (5 phút)
    if (now - ipData.timestamp > 5 * 60 * 1000) {
        ipData = { timestamp: now, blocked: false, count: 0 };
    }
    if (now - deviceData.timestamp > 5 * 60 * 1000) {
        deviceData = { timestamp: now, blocked: false, count: 0 };
    }

    // Kiểm tra IP bị chặn, chặn thiết bị
    if (ipData.blocked) {
        const remainingTime = Math.ceil((ipData.timestamp + 5 * 60 * 1000 - now) / 1000);
        if (remainingTime > 0) {
            logger.info(`IP ${ip} is blocked, blocking device ${fingerprint}, remaining time: ${remainingTime}s`);
            deviceData.blocked = true;
            deviceData.timestamp = now;
            deviceBlocks.set(fingerprint, deviceData);
            return res.json({ status: 429, remainingTime });
        } else {
            ipData.blocked = false;
            ipData.count = 0;
        }
    }

    // Kiểm tra thiết bị bị chặn, chặn IP
    if (deviceData.blocked) {
        const remainingTime = Math.ceil((deviceData.timestamp + 5 * 60 * 1000 - now) / 1000);
        if (remainingTime > 0) {
            logger.info(`Device ${fingerprint} is blocked, blocking IP ${ip}, remaining time: ${remainingTime}s`);
            ipData.blocked = true;
            ipData.timestamp = now;
            ipBlocks.set(ip, ipData);
            return res.json({ status: 429, remainingTime });
        } else {
            deviceData.blocked = false;
            deviceData.count = 0;
        }
    }

    // Cấp token nếu không bị chặn
    const token = crypto.randomBytes(16).toString('hex');
    csrfTokens.set(ip, token);
    setTimeout(() => csrfTokens.delete(ip), 60 * 1000);
    ipBlocks.set(ip, ipData);
    deviceBlocks.set(fingerprint, deviceData);
    logger.info(`Generated CSRF token for IP ${ip}, Device ${fingerprint}`);
    res.json({ csrfToken: token, status: 200 });
});

const checkRateLimitLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    keyGenerator: (req) => req.clientIp,
    handler: (req, res) => {
        logger.info(`Flood limit hit for IP ${req.clientIp}`);
        res.status(429).json({ status: 429, message: 'Too many check requests. Please wait.' });
    }
});

app.get('/check-rate-limit', checkRateLimitLimiter, (req, res) => {
    const ip = req.clientIp;
    const fingerprint = req.clientFingerprint;
    const now = Date.now();

    let ipData = ipBlocks.get(ip) || { timestamp: 0, blocked: false, count: 0 };
    let deviceData = deviceBlocks.get(fingerprint) || { timestamp: 0, blocked: false, count: 0 };

    const ipRemaining = Math.ceil((ipData.timestamp + 5 * 60 * 1000 - now) / 1000);
    const deviceRemaining = Math.ceil((deviceData.timestamp + 5 * 60 * 1000 - now) / 1000);

    if (ipData.blocked && ipRemaining > 0) {
        logger.info(`IP ${ip} is blocked, remaining time: ${ipRemaining}s`);
        return res.json({ status: 429, remainingTime: ipRemaining });
    }
    if (deviceData.blocked && deviceRemaining > 0) {
        logger.info(`Device ${fingerprint} is blocked, remaining time: ${deviceRemaining}s`);
        return res.json({ status: 429, remainingTime: deviceRemaining });
    }

    res.json({ status: 200 });
});

const verifyLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 1,
    keyGenerator: (req) => req.clientIp,
    handler: (req, res) => {
        const ip = req.clientIp;
        const fingerprint = req.clientFingerprint;
        const now = Date.now();
        let ipData = ipBlocks.get(ip) || { timestamp: now, blocked: false, count: 0 };
        let deviceData = deviceBlocks.get(fingerprint) || { timestamp: now, blocked: false, count: 0 };
        const remainingTime = Math.max(
            Math.ceil((ipData.timestamp + 5 * 60 * 1000 - now) / 1000),
            Math.ceil((deviceData.timestamp + 5 * 60 * 1000 - now) / 1000)
        );
        logger.info(`Rate limit hit for IP ${ip}, Fingerprint: ${fingerprint}, remaining time: ${remainingTime}s`);
        res.status(429).json({
            success: false,
            message: 'Too many attempts. Please try again later.',
            status: 429,
            remainingTime: remainingTime > 0 ? remainingTime : 0
        });
    },
    skip: (req) => {
        const ip = req.clientIp;
        const fingerprint = req.clientFingerprint;
        const now = Date.now();
        let ipData = ipBlocks.get(ip) || { timestamp: now, blocked: false, count: 0 };
        let deviceData = deviceBlocks.get(fingerprint) || { timestamp: now, blocked: false, count: 0 };

        // Reset nếu quá thời gian
        if (now - ipData.timestamp > 5 * 60 * 1000) {
            ipData = { timestamp: now, blocked: false, count: 0 };
        }
        if (now - deviceData.timestamp > 5 * 60 * 1000) {
            deviceData = { timestamp: now, blocked: false, count: 0 };
        }

        // Kiểm tra IP bị chặn, chặn thiết bị
        if (ipData.blocked) {
            const remainingTime = Math.ceil((ipData.timestamp + 5 * 60 * 1000 - now) / 1000);
            if (remainingTime > 0) {
                logger.info(`IP ${ip} is blocked, blocking device ${fingerprint}, remaining time: ${remainingTime}s`);
                deviceData.blocked = true;
                deviceData.timestamp = now;
                deviceBlocks.set(fingerprint, deviceData);
                return false;
            } else {
                ipData.blocked = false;
                ipData.count = 0;
            }
        }

        // Kiểm tra thiết bị bị chặn, chặn IP
        if (deviceData.blocked) {
            const remainingTime = Math.ceil((deviceData.timestamp + 5 * 60 * 1000 - now) / 1000);
            if (remainingTime > 0) {
                logger.info(`Device ${fingerprint} is blocked, blocking IP ${ip}, remaining time: ${remainingTime}s`);
                ipData.blocked = true;
                ipData.timestamp = now;
                ipBlocks.set(ip, ipData);
                return false;
            } else {
                deviceData.blocked = false;
                deviceData.count = 0;
            }
        }

        // Cập nhật trạng thái sau verify
        ipData.count += 1;
        deviceData.count += 1;
        if (ipData.count > 1 || deviceData.count > 1) {
            ipData.blocked = true;
            deviceData.blocked = true;
            ipData.timestamp = now;
            deviceData.timestamp = now;
            logger.info(`Blocking IP ${ip} and Device ${fingerprint} after excessive attempts`);
        }
        ipBlocks.set(ip, ipData);
        deviceBlocks.set(fingerprint, deviceData);

        const allow = !ipData.blocked && !deviceData.blocked;
        return allow;
    }
});

app.post('/verify', verifyLimiter, (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse, 'csrf-token': csrfToken, deviceInfo, clientIp } = req.body;
    const ip = req.clientIp;
    const expectedToken = csrfTokens.get(ip);
    const fingerprint = deviceInfo?.fingerprint;

    logger.info(`Verifying for IP ${ip}, Fingerprint: ${fingerprint}, Client IP: ${clientIp}`);

    if (!recaptchaResponse || !csrfToken || !expectedToken || csrfToken !== expectedToken) {
        logger.info('Invalid CSRF token or missing CAPTCHA response');
        return res.json({ success: false, message: 'Invalid CSRF token or missing CAPTCHA response' });
    }

    if (!req.clientDevice || req.clientDevice.includes('bot') || req.clientDevice.includes('spider')) {
        logger.info('Suspicious User-Agent detected:', req.clientDevice);
        return res.json({ success: false, message: 'Suspicious request detected' });
    }

    try {
        axios.post(
            `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaResponse}`
        ).then(response => {
            if (response.data.success) {
                logger.info(`CAPTCHA verified for IP ${ip}`);
                let ipData = ipBlocks.get(ip) || { timestamp: Date.now(), blocked: false, count: 0 };
                let deviceData = deviceBlocks.get(fingerprint) || { timestamp: Date.now(), blocked: false, count: 0 };
                ipData.blocked = true;
                deviceData.blocked = true;
                ipData.timestamp = Date.now();
                deviceData.timestamp = Date.now();
                ipBlocks.set(ip, ipData);
                deviceBlocks.set(fingerprint, deviceData);
                const redirectUrl = 'https://www.example.com/success';
                res.json({
                    success: true,
                    message: 'CAPTCHA verified successfully!',
                    redirectUrl: redirectUrl
                });
            } else {
                logger.info(`CAPTCHA verification failed for IP ${ip}, errors: ${response.data['error-codes']}`);
                res.json({ success: false, message: 'CAPTCHA verification failed' });
            }
        }).catch(error => {
            logger.error(`Error verifying CAPTCHA for IP ${ip}: ${error.message}`);
            res.json({ success: false, message: 'Error verifying CAPTCHA' });
        });
    } catch (error) {
        logger.error(`Exception verifying CAPTCHA for IP ${ip}: ${error.message}`);
        res.json({ success: false, message: 'Error verifying CAPTCHA' });
    }
});

app.use((req, res) => {
    logger.info(`404 Not Found for path: ${req.path}`);
    res.status(404).sendFile('404.html', { root: __dirname + '/public' });
});

app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});
