document.getElementById('captcha-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultElement = document.getElementById('result');
    const debugElement = document.getElementById('debug');
    
    // Reset previous states
    resultElement.innerText = '';
    resultElement.className = '';
    debugElement.innerText = '';
    debugElement.className = 'debug-panel';

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
            headers: { 'Content-Type': 'application/json' },
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

        // Redirect to success page after 2 seconds if verification is successful
        if (data.success) {
            setTimeout(() => {
                window.location.href = 'https://www.example.com/success'; // Thay bằng URL mong muốn
            }, 2000);
        }
    } catch (error) {
        resultElement.innerText = 'Error verifying CAPTCHA';
        resultElement.className = 'error';
        debugElement.innerText = `Client Error: ${error.message}`;
        debugElement.className = 'debug-panel active';
    }
});
