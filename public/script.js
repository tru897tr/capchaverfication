document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('captcha-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const resultElement = document.getElementById('result');
        const redirectButton = document.getElementById('redirect-button');
        resultElement.innerText = '';
        redirectButton.style.display = 'none';

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

            if (data.success) {
                redirectButton.style.display = 'block';
            }
        } catch (error) {
            resultElement.innerText = 'Error verifying CAPTCHA';
            resultElement.className = 'error';
        }
    });

    document.getElementById('redirect-button').addEventListener('click', () => {
        window.location.href = 'https://www.example.com/success'; // Thay bằng URL thực tế
    });
});
