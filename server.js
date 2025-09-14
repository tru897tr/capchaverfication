const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Lưu trữ trạng thái rate limit trong bộ nhớ (in-memory store)
const requestTimes = new Map(); // Map<IP+User-Agent, { timestamp: number, count: number }>

app.use(express.json());
app.use(express.static('public'));

// Middleware để lấy IP và User-Agent của client
app.use((req, res, next) => {
    req.clientIp = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    req.clientDevice = req.headers['user-agent'] || 'unknown';
    req.clientKey = `${req.clientIp}:${req.clientDevice}`; // Kết hợp IP và User-Agent làm key
    next();
});

// Rate limiting: 1 request mỗi 3 phút mỗi IP + thiết bị
const verifyLimiter = rateLimit({
    windowMs: 3 * 60 * 1000, // 3 phút
    max: 1, // Giới hạn 1 request
    keyGenerator: (req) => req.clientKey, // Sử dụng IP + User-Agent làm key
    handler: (req, res) => {
        const ipData = requestTimes.get(req.clientKey) || { timestamp: 0, count: 0 };
        const remainingTime = Math.ceil((ipData.timestamp + 3 * 60 * 1000 - Date.now()) / 1000);
        res.status(429).json({
            success: false,
            message: 'Too many attempts. Please try again later.',
            status: 429,
            remainingTime: remainingTime > 0 ? remainingTime : 0
        });
    },
    skip: (req) => {
        const key = req.clientKey;
        const now = Date.now();
        let ipData = requestTimes.get(key);

        // Nếu không có dữ liệu hoặc đã quá 3 phút, reset
        if (!ipData || now - ipData.timestamp >= 3 * 60 * 1000) {
            requestTimes.set(key, { timestamp: now, count: 0 });
            ipData = requestTimes.get(key);
        }

        // Tăng số lần request và cập nhật timestamp
        ipData.count += 1;
        ipData.timestamp = now;
        requestTimes.set(key, ipData);

        // Cho phép nếu count <= 1, chặn nếu count > 1
        const allow = ipData.count <= 1;
        return allow;
    }
});

// Route xác minh CAPTCHA
app.post('/verify', verifyLimiter, async (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse } = req.body;
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    if (!recaptchaResponse || !secretKey) {
        return res.json({ success: false, message: 'Missing CAPTCHA response or secret key' });
    }

    try {
        const response = await axios.post(
            `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaResponse}`
        );

        if (response.data.success) {
            // Trả về link chuyển hướng chỉ khi CAPTCHA thành công
            const redirectUrl = 'https://www.example.com/success'; // Thay bằng URL thực tế
            res.json({ success: true, message: 'CAPTCHA verified successfully!', redirectUrl });
        } else {
            res.json({ success: false, message: 'CAPTCHA verification failed' });
        }
    } catch (error) {
        res.json({ success: false, message: 'Error verifying CAPTCHA' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
