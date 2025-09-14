const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Lưu trữ trạng thái rate limit và CSRF token
const requestTimes = new Map(); // Map<IP, { timestamp: number, count: number, devices: Set }>
const csrfTokens = new Map(); // Map<IP, CSRF token>

app.use(express.json());
app.use(express.static('public'));

// Middleware để lấy IP của client
app.use((req, res, next) => {
    req.clientIp = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    req.clientDevice = req.headers['user-agent'] || 'unknown';
    console.log(`Request from IP: ${req.clientIp}, Device: ${req.clientDevice}`);
    next();
});

// Tạo và gửi token CSRF
app.get('/get-csrf-token', (req, res) => {
    const ip = req.clientIp;
    const token = crypto.randomBytes(16).toString('hex');
    csrfTokens.set(ip, token);
    setTimeout(() => csrfTokens.delete(ip), 10 * 60 * 1000); // Hết hạn sau 10 phút
    console.log(`Generated CSRF token for IP ${ip}: ${token}`);
    res.json({ csrfToken: token });
});

// Kiểm tra trạng thái rate limit
app.get('/check-rate-limit', (req, res) => {
    const ip = req.clientIp;
    const ipData = requestTimes.get(ip) || { timestamp: 0, count: 0, devices: new Set() };
    const now = Date.now();
    const remainingTime = Math.ceil((ipData.timestamp + 5 * 60 * 1000 - now) / 1000);

    console.log(`Checking rate limit for IP ${ip}, count: ${ipData.count}, remainingTime: ${remainingTime}s`);
    if (remainingTime > 0 && ipData.count > 0) {
        res.json({
            status: 429,
            remainingTime: remainingTime
        });
    } else {
        res.json({ status: 200 });
    }
});

// Rate limiting: 1 request mỗi 5 phút mỗi IP
const verifyLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 phút
    max: 1, // Giới hạn 1 request
    keyGenerator: (req) => req.clientIp, // Chỉ sử dụng IP làm key
    handler: (req, res) => {
        const ipData = requestTimes.get(req.clientIp) || { timestamp: 0, count: 0 };
        const remainingTime = Math.ceil((ipData.timestamp + 5 * 60 * 1000 - Date.now()) / 1000);
        console.log(`Rate limit hit for IP ${req.clientIp}, remaining time: ${remainingTime}s`);
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
            requestTimes.set(ip, { timestamp: now, count: 0, devices: new Set() });
            ipData = requestTimes.get(ip);
        }

        const device = req.clientDevice;
        const existingDevices = ipData.devices;
        if (!existingDevices.has(device)) {
            existingDevices.add(device);
            ipData.devices = existingDevices;
            requestTimes.set(ip, ipData);
            if (ipData.count > 0) {
                console.log(`New device ${device} on IP ${ip} blocked, count: ${ipData.count}`);
                return false; // Chặn thiết bị mới nếu IP đã dùng quota
            }
        }

        ipData.count += 1;
        ipData.timestamp = now;
        requestTimes.set(ip, ipData);
        console.log(`Updated IP ${ip}, count: ${ipData.count}, timestamp: ${ipData.timestamp}`);

        const allow = ipData.count <= 1;
        return allow;
    }
});

// Route xác minh CAPTCHA với CSRF
app.post('/verify', verifyLimiter, (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse, 'csrf-token': csrfToken, clientIp, clientDevice } = req.body;
    const ip = req.clientIp;
    const expectedToken = csrfTokens.get(ip);

    console.log(`Verifying for IP ${ip}, Device ${clientDevice}, Client IP ${clientIp}, CSRF token: ${csrfToken}`);

    if (!recaptchaResponse || !csrfToken || !expectedToken || csrfToken !== expectedToken) {
        console.log('Invalid CSRF token or missing CAPTCHA response');
        return res.json({ success: false, message: 'Invalid CSRF token or missing CAPTCHA response' });
    }

    if (!clientIp || !clientDevice) {
        console.log('Missing client IP or device information');
        return res.json({ success: false, message: 'Missing client information' });
    }

    try {
        axios.post(
            `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaResponse}`
        ).then(response => {
            if (response.data.success) {
                console.log(`CAPTCHA verified for IP ${ip}, Device ${clientDevice}`);
                const redirectUrl = 'https://www.example.com/success'; // Thay bằng URL thực tế
                res.json({
                    success: true,
                    message: 'CAPTCHA verified successfully!',
                    redirectUrl: clientIp && clientDevice ? redirectUrl : null // Chỉ trả link nếu có IP và thiết bị
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
