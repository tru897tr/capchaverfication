const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const winston = require('winston');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Cấu hình logging với Winston để hiển thị trên Render stdout
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console() // Ghi log ra stdout cho Render
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.File({ filename: 'combined.log' }));
}

// Lưu trữ trạng thái rate limit và CSRF token
const requestTimes = new Map(); // Map<fingerprint, { timestamp: number, count: number, ipBlocked: Map<IP, boolean> }>
const csrfTokens = new Map(); // Map<IP, CSRF token>
const checkLimitTimes = new Map();

app.use(express.json());
app.use(express.static('public', { etag: false, lastModified: false })); // Ngăn cache tĩnh

app.use((req, res, next) => {
    req.clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || req.connection.remoteAddress;
    req.clientDevice = req.headers['user-agent'] || 'unknown';
    req.clientFingerprint = req.body.deviceInfo ? req.body.deviceInfo.fingerprint : `${req.clientIp}-${req.clientDevice}-${req.headers['accept'] || ''}`.slice(0, 100);
    logger.info(`Request from IP: ${req.clientIp}, Device: ${req.clientDevice}, Fingerprint: ${req.clientFingerprint}`);
    next();
});

app.post('/get-csrf-token', (req, res) => {
    const ip = req.clientIp;
    const { deviceInfo } = req.body;
    const fingerprint = deviceInfo.fingerprint;
    const now = Date.now();
    let deviceData = requestTimes.get(fingerprint) || { timestamp: now, count: 0, ipBlocked: new Map() };

    // Kiểm tra nếu IP đã bị chặn từ bất kỳ fingerprint nào
    for (let [existingFingerprint, data] of requestTimes.entries()) {
        if (data.ipBlocked.get(ip) && existingFingerprint !== fingerprint) {
            const remainingTime = Math.ceil((data.timestamp + 5 * 60 * 1000 - now) / 1000);
            if (remainingTime > 0) {
                logger.info(`IP ${ip} blocked from Fingerprint ${existingFingerprint}, blocking new Fingerprint ${fingerprint}`);
                deviceData.ipBlocked.set(ip, true);
                deviceData.timestamp = now;
                requestTimes.set(fingerprint, deviceData);
                return res.json({ status: 429, remainingTime });
            }
        }
    }

    // Kiểm tra nếu fingerprint đã bị chặn từ bất kỳ IP nào
    if (deviceData.ipBlocked.size > 0) {
        const remainingTime = Math.ceil((deviceData.timestamp + 5 * 60 * 1000 - now) / 1000);
        if (remainingTime > 0) {
            if (deviceData.ipBlocked.get(ip) || [...deviceData.ipBlocked.values()].some(blocked => blocked)) {
                logger.info(`Fingerprint ${fingerprint} or IP ${ip} blocked, remaining time: ${remainingTime}s`);
                return res.json({ status: 429, remainingTime });
            }
        } else {
            deviceData.ipBlocked.clear();
            deviceData.count = 0;
        }
    }

    const token = crypto.randomBytes(16).toString('hex');
    csrfTokens.set(ip, token);
    setTimeout(() => csrfTokens.delete(ip), 60 * 1000);
    requestTimes.set(fingerprint, deviceData);
    logger.info(`Generated CSRF token for IP ${ip}`);
    res.json({ csrfToken: token, status: 200 });
});

const checkRateLimitLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    keyGenerator: (req) => req.clientIp,
    handler: (req, res) => {
        logger.info(`Flood limit hit for IP ${req.clientIp}`);
        res.status(429).json({
            status: 429,
            message: 'Too many check requests. Please wait.'
        });
    }
});

app.get('/check-rate-limit', checkRateLimitLimiter, (req, res) => {
    const ip = req.clientIp;
    const fingerprint = req.clientFingerprint;
    let deviceData = requestTimes.get(fingerprint) || { timestamp: 0, count: 0, ipBlocked: new Map() };
    const now = Date.now();
    
    if (!deviceData || now - deviceData.timestamp >= 5 * 60 * 1000) {
        deviceData = { timestamp: now, count: 0, ipBlocked: new Map() };
        requestTimes.set(fingerprint, deviceData);
    }

    const remainingTime = Math.ceil((deviceData.timestamp + 5 * 60 * 1000 - now) / 1000);
    const ipBlocked = deviceData.ipBlocked.get(ip) || false;

    logger.info(`Checking rate limit for IP ${ip}, Fingerprint: ${fingerprint}, count: ${deviceData.count}, remainingTime: ${remainingTime}s, IP Blocked: ${ipBlocked}`);
    if (remainingTime > 0 && (deviceData.count > 0 || ipBlocked)) {
        res.json({
            status: 429,
            remainingTime: remainingTime
        });
    } else {
        res.json({ status: 200 });
    }
});

const verifyLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 1,
    keyGenerator: (req) => req.clientIp,
    handler: (req, res) => {
        const fingerprint = req.clientFingerprint;
        const ip = req.clientIp;
        const deviceData = requestTimes.get(fingerprint) || { timestamp: 0, count: 0, ipBlocked: new Map() };
        const remainingTime = Math.ceil((deviceData.timestamp + 5 * 60 * 1000 - Date.now()) / 1000);
        logger.info(`Rate limit hit for IP ${ip}, Fingerprint: ${fingerprint}, remaining time: ${remainingTime}s, IP Blocked: ${deviceData.ipBlocked.get(ip)}`);
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
        let deviceData = requestTimes.get(fingerprint);

        if (!deviceData || now - deviceData.timestamp >= 5 * 60 * 1000) {
            deviceData = { timestamp: now, count: 0, ipBlocked: new Map() };
            requestTimes.set(fingerprint, deviceData);
        }

        // Kiểm tra nếu IP đã bị chặn từ bất kỳ fingerprint nào
        for (let [existingFingerprint, data] of requestTimes.entries()) {
            if (data.ipBlocked.get(ip) && existingFingerprint !== fingerprint) {
                const remainingTime = Math.ceil((data.timestamp + 5 * 60 * 1000 - now) / 1000);
                if (remainingTime > 0) {
                    logger.info(`IP ${ip} blocked from Fingerprint ${existingFingerprint}, blocking new Fingerprint ${fingerprint}`);
                    deviceData.ipBlocked.set(ip, true);
                    deviceData.timestamp = now;
                    requestTimes.set(fingerprint, deviceData);
                    return false;
                }
            }
        }

        // Kiểm tra nếu fingerprint đã bị chặn từ IP khác
        if (deviceData.ipBlocked.size > 0) {
            const remainingTime = Math.ceil((deviceData.timestamp + 5 * 60 * 1000 - now) / 1000);
            if (remainingTime > 0 && [...deviceData.ipBlocked.values()].some(blocked => blocked)) {
                logger.info(`Fingerprint ${fingerprint} blocked, checking IP ${ip}`);
                deviceData.ipBlocked.set(ip, true);
                requestTimes.set(fingerprint, deviceData);
                return false;
            }
        }

        deviceData.count += 1;
        deviceData.timestamp = now;
        if (deviceData.count > 1) {
            deviceData.ipBlocked.set(ip, true);
            logger.info(`Blocking IP ${ip} and Fingerprint ${fingerprint} after verification`);
        }
        requestTimes.set(fingerprint, deviceData);

        const allow = deviceData.count <= 1 && !deviceData.ipBlocked.get(ip);
        return allow;
    }
});

app.post('/verify', verifyLimiter, (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse, 'csrf-token': csrfToken, deviceInfo } = req.body;
    const ip = req.clientIp;
    const expectedToken = csrfTokens.get(ip);
    const fingerprint = deviceInfo.fingerprint;

    logger.info(`Verifying for IP ${ip}, Fingerprint: ${fingerprint}`);

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
                const redirectUrl = 'https://www.example.com/success';
                // Chặn ngay sau verify thành công
                let deviceData = requestTimes.get(fingerprint) || { timestamp: Date.now(), count: 1, ipBlocked: new Map() };
                deviceData.ipBlocked.set(ip, true);
                deviceData.timestamp = Date.now();
                requestTimes.set(fingerprint, deviceData);
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

app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});
