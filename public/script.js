// Hàm kiểm tra phản hồi JSON
async function parseResponse(response) {
    const text = await response.text();
    try {
        return JSON.parse(text);
    } catch (error) {
        throw new Error(`Invalid JSON response: ${text.slice(0, 50)}...`);
    }
}

// Lấy CSRF token từ server khi trang tải
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch('/csrf-token', {
            method: 'GET',
            credentials: 'include' // Gửi cookie session
        });
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        const data = await parseResponse(res);
        document.getElementById('csrf-token').value = data.csrfToken;
        console.log('CSRF token fetched:', data.csrfToken); // Debug
        console.log('Cookies:', document.cookie); // Kiểm tra cookie session
    } catch (error) {
        document.getElementById('result').innerText = 'Error fetching CSRF token';
        document.getElementById('result').className = 'error';
        document.getElementById('debug').innerText = `Client Error: ${error.message}`;
        document.getElementById('debug').className = 'debug-panel active';
        console.error('CSRF token error:', error);
    }
});

document.getElementById('captcha-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultElement = document.getElementById('result');
    const debugElement = document.getElementById('debug');
    const redirectButton = document.getElementById('redirect-button');
    const csrfToken = document.getElementById('csrf-token').value;
    
    // Reset previous states
    resultElement.innerText = '';
    resultElement.className = '';
    debugElement.innerText = '';
    debugElement.className = 'debug-panel';
    redirectButton.style.display = 'none';

    const response = grecaptcha.getResponse();
    if (!response) {
        resultElement.innerText = 'Please complete the CAPTCHA';
        resultElement.className = 'error';
        debugElement.innerText = 'Client Error: No CAPTCHA response provided';
        debugElement.className = 'debug-panel active';
        return;
    }

    try {
        console.log('Sending verify request with CSRF token:', csrfToken); // Debug
        console.log('Current cookies:', document.cookie); // Kiểm tra cookie trước khi gửi
        const res = await fetch('/verify', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include', // Gửi cookie session
            body: JSON.stringify({ 'g-recaptcha-response': response })
        });

        if (!res.ok) {
            const data = await parseResponse(res);
            throw new Error(`HTTP ${res.status}: ${data.message || res.statusText}`);
        }
        const data = await parseResponse(res);
        resultElement.innerText = data.message;
        resultElement.className = data.success ? 'success' : 'error';
        
        // Show debug only on error
        if (!data.success) {
            debugElement.innerText = data.debug || 'Client Error: Verification failed';
            debugElement.className = 'debug-panel active';
        }

        // Show redirect button on success
        if (data.success) {
            redirectButton.style.display = 'block';
        }
    } catch (error) {
        resultElement.innerText = 'Error verifying CAPTCHA';
        resultElement.className = 'error';
        debugElement.innerText = `Client Error: ${error.message}`;
        debugElement.className = 'debug-panel active';
        console.error('Verify error:', error);
    }
});

// Redirect when "Về" button is clicked
document.getElementById('redirect-button').addEventListener('click', async () => {
    try {
        const csrfToken = document.getElementById('csrf-token').value;
        console.log('Sending redirect request with CSRF token:', csrfToken); // Debug
        console.log('Current cookies:', document.cookie); // Kiểm tra cookie trước khi gửi
        const res = await fetch('/get-redirect', {
            method: 'GET',
            headers: { 'X-CSRF-Token': csrfToken },
            credentials: 'include' // Gửi cookie session
        });
        if (!res.ok) {
            const data = await parseResponse(res);
            throw new Error(`HTTP ${res.status}: ${data.message || res.statusText}`);
        }
        const data = await parseResponse(res);
        if (data.redirectUrl) {
            window.location.href = data.redirectUrl;
        } else {
            document.getElementById('result').innerText = 'Error: Invalid session';
            document.getElementById('result').className = 'error';
            document.getElementById('debug').innerText = 'Client Error: No valid redirect URL';
            document.getElementById('debug').className = 'debug-panel active';
        }
    } catch (error) {
        document.getElementById('result').innerText = 'Error fetching redirect URL';
        document.getElementById('result').className = 'error';
        document.getElementById('debug').innerText = `Client Error: ${error.message}`;
        document.getElementById('debug').className = 'debug-panel active';
        console.error('Redirect error:', error);
    }
});
