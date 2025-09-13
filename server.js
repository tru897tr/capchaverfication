const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware bảo mật
app.use(helmet()); // Thêm các tiêu đề HTTP bảo mật
app.use(express.json());
app.use(express.static('public'));
app.use(csrf()); // CSRF protection

// Rate limiting để ngăn brute force
const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 phút
    max: 10, // Giới hạn 10 request mỗi IP
    message: {
        success: false,
        message: 'Too many attempts, please try again later.',
        debug: 'Server Error: Rate limit exceeded'
    }
});

// Route để lấy CSRF token
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Route để xử lý xác minh CAPTCHA
app.post('/verify', verifyLimiter, async (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse } = req.body;
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    if (!recaptchaResponse) {
        return res.status(400).json({
            success: false,
            message: 'No CAPTCHA response provided',
            debug: 'Server Error: Missing g-recaptcha-response in request body'
        });
    }

    try {
        const response = await axios.post(
            `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaResponse}`
        );

        if (response.data.success) {
            res.json({
                success: true,
                message: 'CAPTCHA verified successfully!'
            });
        } else {
            res.status(400).json({
                success: false,
                message: 'CAPTCHA verification failed',
                debug: `Server: Verification failed. Errors: ${JSON.stringify(response.data['error-codes'] || [])}`
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Server error during CAPTCHA verification',
            debug: `Server Error: ${error.message}`
        });
    }
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
