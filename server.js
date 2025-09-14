const express = require('express');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.static('public'));

// Route xác minh CAPTCHA
app.post('/verify', async (req, res) => {
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

// Route Get Link (ẩn, chỉ trả về khi verify thành công qua /verify)
app.get('/get-redirect', (req, res) => {
    // Không cho phép truy cập trực tiếp, yêu cầu verify trước
    res.status(403).json({ success: false, message: 'Access denied. Complete CAPTCHA first.' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
