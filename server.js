const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Kết nối Redis
const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://red-d32s42umcj7s739sskrg:6379'
});

redisClient.on('error', (err) => {
    console.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
    console.log('Connected to Redis successfully');
});

redisClient.on('ready', () => {
    console.log('Redis is ready to accept commands');
});

redisClient.connect().catch((err) => {
    console.error('Redis Connection Failed:', err);
});

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

// Session middleware với Redis
let sessionStore;
try {
    sessionStore = new RedisStore({ client: redisClient });
} catch (error) {
    console.error('Redis Store Error, falling back to MemoryStore:', error);
    sessionStore = new session.MemoryStore(); // Fallback chỉ cho dev
}

app.use(session({
    store: sessionStore,
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // HTTPS trên Render
        httpOnly: true, 
        sameSite: 'strict', // Thêm để tăng bảo mật
        maxAge: 15 * 60 * 1000 // 15 phút
    }
}));

// CSRF protection
app.use(csrf({ cookie: false }));

// Rate limiting
const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 phút
    max: 10, // Tăng lên 10 để debug dễ hơn
    message: {
        success: false,
        message: 'Too many attempts, please try again later.',
        debug: 'Server Error: Rate limit exceeded'
    }
});

// Chỉ cho phép phương thức HTTP đúng
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
        console.error('CSRF Error:', {
            path: req.path,
            method: req.method,
            session: req.sessionID
        });
        return res.status(403).json({
            success: false,
            message: 'Invalid CSRF token',
            debug: 'Server Error: CSRF token validation failed'
        });
    }
    next();
});

// Route lấy CSRF token
app.get('/csrf-token', (req, res) => {
    try {
        console.log('Generating CSRF token for session:', req.sessionID); // Debug
        res.json({ csrfToken: req.csrfToken() });
    } catch (error) {
        console.error('CSRF Token Generation Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error generating CSRF token',
            debug: `Server Error: ${error.message}`
        });
    }
});

// Route xác minh CAPTCHA
app.post('/verify', verifyLimiter, async (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse } = req.body;
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    console.log('Verify request received:', {
        session: req.sessionID,
        recaptchaResponse: !!recaptchaResponse
    }); // Debug

    if (!secretKey) {
        console.error('Missing RECAPTCHA_SECRET_KEY');
        return res.status(500).json({
            success: false,
            message: 'Server configuration error',
            debug: 'Server Error: RECAPTCHA_SECRET_KEY not set'
        });
    }

    if (!recaptchaResponse) {
        console.error('Missing CAPTCHA response');
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

        console.log('reCAPTCHA response:', response.data); // Debug

        if (response.data.success) {
            req.session.isVerified = true;
            console.log('Session updated, isVerified:', req.session.isVerified); // Debug
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
        console.error('CAPTCHA Verification Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during CAPTCHA verification',
            debug: `Server Error: ${error.message}`
        });
    }
});

// Route lấy URL chuyển hướng
app.get('/get-redirect', (req, res) => {
    console.log('Get-redirect request, session:', {
        sessionID: req.sessionID,
        isVerified: req.session.isVerified
    }); // Debug
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
        console.error('Redirect URL Error:', error);
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
