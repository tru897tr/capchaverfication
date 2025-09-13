document.getElementById('captcha-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultElement = document.getElementById('result');
    
    // Reset previous states
    resultElement.innerText = '';
    resultElement.className = '';

    const response = grecaptcha.getResponse();
    if (!response) {
        resultElement.innerText = 'Please complete the CAPTCHA';
        resultElement.className = 'error';
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

        // Redirect to success page after 2 seconds if verification is successful
        if (data.success) {
            setTimeout(() => {
                window.location.href = 'https://www.example.com/success'; // Thay bằng URL mong muốn
            }, 2000);
        }
    } catch (error) {
        resultElement.innerText = 'Error verifying CAPTCHA';
        resultElement.className = 'error';
    }
});
