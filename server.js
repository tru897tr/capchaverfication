const express = require('express');
const axios = require('axios');
const cors = require('cors');
const app = express();

const SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || '6LeBicYrAAAAAFABk9WjdpLt_LdAWCw27hKvad4A';
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Phục vụ index.html

// Redirect từ / đến /captcha
app.get('/', (req, res) => {
  res.redirect('/captcha');
});

// Phục vụ index.html tại /captcha
app.get('/captcha', (req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

// Xử lý xác minh reCAPTCHA
app.post('/captcha/verify', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ success: false, error: 'No token provided' });
  }

  try {
    const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
      params: { secret: SECRET_KEY, response: token }
    });

    const { success, score, 'error-codes': errorCodes } = response.data;
    res.json({
      success,
      score,
      error: errorCodes ? errorCodes.join(', ') : null
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
