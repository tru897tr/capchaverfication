// Giải mã URL bằng base64
const encodedRedirectUrl = 'aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vc3VjY2Vzcw=='; // Mã hóa base64 của https://www.example.com/success
const redirectUrl = atob(encodedRedirectUrl); // Giải mã URL

// Lấy CSRF token từ server khi trang tải
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch('/csrf-token');
        const data = await res.json();
        document.getElementById('csrf-token').value = data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
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
document.getElementById('redirect-button').addEventListener('click', () => {
    window.location.href = redirectUrl;
});
