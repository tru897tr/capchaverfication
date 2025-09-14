const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Lưu trữ trạng thái rate limit và CSRF token
const requestTimes = new Map();
const csrfTokens = new Map();
const checkLimitTimes = new Map();

app.use(express.json());
app.use(express.static('public'));

app.use((req, res, next) => {
    req.clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || req.connection.remoteAddress;
    req.clientDevice = req.headers['user-agent'] || 'unknown';
    req.clientFingerprint = `${req.clientIp}-${req.clientDevice}-${req.headers['accept'] || ''}`.slice(0, 100);
    console.log(`Request from IP: ${req.clientIp}, Device: ${req.clientDevice}, Fingerprint: ${req.clientFingerprint}, X-Forwarded-For: ${req.headers['x-forwarded-for'] || 'N/A'}`);
    next();
});

app.get('/get-csrf-token', (req, res) => {
    const ip = req.clientIp;
    const token = crypto.randomBytes(16).toString('hex');
    csrfTokens.set(ip, token);
    setTimeout(() => csrfTokens.delete(ip), 60 * 1000);
    console.log(`Generated CSRF token for IP ${ip}: ${token}`);
    res.json({ csrfToken: token });
});

const checkRateLimitLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    keyGenerator: (req) => req.clientIp,
    handler: (req, res) => {
        console.log(`Flood limit hit for IP ${req.clientIp}`);
        res.status(429).json({
            status: 429,
            message: 'Too many check requests. Please wait.'
        });
    }
});

app.get('/check-rate-limit', checkRateLimitLimiter, (req, res) => {
    const ip = req.clientIp;
    let ipData = requestTimes.get(ip);
    const now = Date.now();
    
    if (!ipData || now - ipData.timestamp >= 5 * 60 * 1000) {
        requestTimes.set(ip, { timestamp: now, count: 0 });
        ipData = requestTimes.get(ip);
    }

    const remainingTime = Math.ceil((ipData.timestamp + 5 * 60 * 1000 - now) / 1000);

    console.log(`Checking rate limit for IP ${ip}, count: ${ipData.count}, remainingTime: ${remainingTime}s, Fingerprint: ${req.clientFingerprint}`);
    if (remainingTime > 0 && ipData.count > 0) {
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
        const ipData = requestTimes.get(req.clientIp) || { timestamp: 0, count: 0 };
        const remainingTime = Math.ceil((ipData.timestamp + 5 * 60 * 1000 - Date.now()) / 1000);
        console.log(`Rate limit hit for IP ${req.clientIp}, remaining time: ${remainingTime}s, Fingerprint: ${req.clientFingerprint}`);
        res.status(429).json({
            success: false,
            message: 'Too many attempts. Please try again later.',
            status: 429,
            remainingTime: remainingTime > 0 ? remainingTime : 0
        });
    },
    skip: (req) => {
        const ip = req.clientIp;
        const now = Date.now();
        let ipData = requestTimes.get(ip);

        if (!ipData || now - ipData.timestamp >= 5 * 60 * 1000) {
            requestTimes.set(ip, { timestamp: now, count: 0 });
            ipData = requestTimes.get(ip);
        }

        if (ipData.fingerprint && ipData.fingerprint !== req.clientFingerprint) {
            console.log(`Fingerprint mismatch for IP ${ip}, old: ${ipData.fingerprint}, new: ${req.clientFingerprint}`);
            return false;
        }

        ipData.count += 1;
        ipData.timestamp = now;
        ipData.fingerprint = req.clientFingerprint;
        requestTimes.set(ip, ipData);

        const allow = ipData.count <= 1;
        return allow;
    }
});

app.post('/verify', verifyLimiter, (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse, 'csrf-token': csrfToken } = req.body;
    const ip = req.clientIp;
    const expectedToken = csrfTokens.get(ip);

    console.log(`Verifying for IP ${ip}, CSRF token: ${csrfToken}, Fingerprint: ${req.clientFingerprint}`);

    if (!recaptchaResponse || !csrfToken || !expectedToken || csrfToken !== expectedToken) {
        console.log('Invalid CSRF token or missing CAPTCHA response');
        return res.json({ success: false, message: 'Invalid CSRF token or missing CAPTCHA response' });
    }

    if (!req.clientDevice || req.clientDevice.includes('bot') || req.clientDevice.includes('spider')) {
        console.log('Suspicious User-Agent detected:', req.clientDevice);
        return res.json({ success: false, message: 'Suspicious request detected' });
    }

    try {
        axios.post(
            `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaResponse}`
        ).then(response => {
            if (response.data.success) {
                console.log(`CAPTCHA verified for IP ${ip}`);
                const redirectUrl = 'https://www.example.com/success';
                res.json({
                    success: true,
                    message: 'CAPTCHA verified successfully!',
                    redirectUrl: redirectUrl
                });
            } else {
                console.log(`CAPTCHA verification failed for IP ${ip}, errors: ${response.data['error-codes']}`);
                res.json({ success: false, message: 'CAPTCHA verification failed' });
            }
        }).catch(error => {
            console.error(`Error verifying CAPTCHA for IP ${ip}:`, error.message);
            res.json({ success: false, message: 'Error verifying CAPTCHA' });
        });
    } catch (error) {
        console.error(`Exception verifying CAPTCHA for IP ${ip}:`, error.message);
        res.json({ success: false, message: 'Error verifying CAPTCHA' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
