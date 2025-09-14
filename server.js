const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.static('public'));

// Rate limiting: 1 request mỗi 3 phút mỗi IP
const verifyLimiter = rateLimit({
    windowMs: 3 * 60 * 1000, // 3 phút
    max: 1, // Giới hạn 1 request
    message: { success: false, message: 'Too many attempts. Please try again later.' },
    handler: (req, res, next, options) => {
        const remainingTime = Math.ceil((options.windowMs - (Date.now() - req.rateLimit.resetTime)) / 1000);
        res.status(429).json({
            success: false,
            message: 'Too many attempts. Please try again later.',
            remainingTime
        });
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
