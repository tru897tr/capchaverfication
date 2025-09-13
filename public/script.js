// Lấy CSRF token từ server khi trang tải
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch('/csrf-token');
        const data = await res.json();
        document.getElementById('csrf-token').value = data.csrfToken;
    } catch (error) {
        document.getElementById('result').innerText = 'Error fetching CSRF token';
        document.getElementById('result').className = 'error';
        document.getElementById('debug').innerText = `Client Error: ${error.message}`;
        document.getElementById('debug').className = 'debug-panel active';
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
        const res = await fetch('/verify', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ 'g-recaptcha-response': response })
        });

        const data = await res.json();
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
    }
});

// Redirect when "Về" button is clicked
document.getElementById('redirect-button').addEventListener('click', async () => {
    try {
        const res = await fetch('/get-redirect', {
            headers: { 'X-CSRF-Token': document.getElementById('csrf-token').value }
        });
        const data = await res.json();
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
    }
});
