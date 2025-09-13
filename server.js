const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Mã hóa URL chuyển hướng
const redirectUrl = 'https://www.example.com/success'; // Thay bằng URL thực tế
const encryptionKey = crypto.randomBytes(32).toString('hex');
const iv = crypto.randomBytes(16);

// Mã hóa URL
function encryptUrl(url) {
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), iv);
    let encrypted = cipher.update(url, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Giải mã URL
function decryptUrl(encrypted) {
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        throw new Error('Invalid decryption');
    }
}

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", 'https://www.google.com', 'https://www.gstatic.com'],
            styleSrc: ["'self'", "'unsafe-inline'"],
            frameSrc: ['https://www.google.com'],
            connectSrc: ["'self'", 'https://www.google.com']
        }
    }
}));
app.use(express.json());
app.use(express.static('public'));

// Session middleware
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // HTTPS trên Render, HTTP cục bộ
        httpOnly: true, 
        maxAge: 15 * 60 * 1000 // 15 phút
    }
}));

// CSRF protection
app.use(csrf({ cookie: false }));

// Rate limiting
const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 phút
    max: 5, // Giới hạn 5 request mỗi IP
    message: {
        success: false,
        message: 'Too many attempts, please try again later.',
        debug: 'Server Error: Rate limit exceeded'
    }
});

// Chỉ cho phép POST cho /verify và GET cho /csrf-token, /get-redirect
app.use((req, res, next) => {
    const allowedMethods = {
        '/verify': ['POST'],
        '/csrf-token': ['GET'],
        '/get-redirect': ['GET']
    };
    const allowed = allowedMethods[req.path];
    if (allowed && !allowed.includes(req.method)) {
        return res.status(405).json({
            success: false,
            message: 'Method not allowed',
            debug: `Server Error: ${req.method} not allowed for ${req.path}`
        });
    }
    next();
});

// Xử lý lỗi CSRF
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({
            success: false,
            message: 'Invalid CSRF token',
            debug: 'Server Error: CSRF token validation failed'
        });
    }
    next();
});

// Route để lấy CSRF token
app.get('/csrf-token', (req, res) => {
    try {
        res.json({ csrfToken: req.csrfToken() });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error generating CSRF token',
            debug: `Server Error: ${error.message}`
        });
    }
});

// Route để xử lý xác minh CAPTCHA
app.post('/verify', verifyLimiter, async (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse } = req.body;
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    if (!secretKey) {
        return res.status(500).json({
            success: false,
            message: 'Server configuration error',
            debug: 'Server Error: RECAPTCHA_SECRET_KEY not set'
        });
    }

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
            req.session.isVerified = true;
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

// Route để lấy URL chuyển hướng
app.get('/get-redirect', (req, res) => {
    if (!req.session.isVerified) {
        return res.status(403).json({
            success: false,
            message: 'Unauthorized: CAPTCHA not verified',
            debug: 'Server Error: No valid session found'
        });
    }
    try {
        const encryptedUrl = encryptUrl(redirectUrl);
        res.json({ redirectUrl: decryptUrl(encryptedUrl) });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error generating redirect URL',
            debug: `Server Error: ${error.message}`
        });
    }
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
