const express = require('express');
const axios = require('axios');
const cors = require('cors');
const app = express();

const SECRET_KEY = '6LeBicYrAAAAAFABk9WjdpLt_LdAWCw27hKvad4A';
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Phục vụ file tĩnh như index.html

app.post('/verify', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ success: false, error: 'No token provided' });
  }

  try {
    const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
      params: {
        secret: SECRET_KEY,
        response: token
      }
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
