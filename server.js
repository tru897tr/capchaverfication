const express = require('express');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

// Route để xử lý xác minh CAPTCHA
app.post('/verify', async (req, res) => {
    const { 'g-recaptcha-response': recaptchaResponse } = req.body;
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    if (!recaptchaResponse) {
        return res.status(400).json({
            success: false,
            message: 'No CAPTCHA response provided'
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
                message: 'CAPTCHA verification failed'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Server error during CAPTCHA verification'
        });
    }
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
