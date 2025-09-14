function submitForm() {
    const resultElement = document.getElementById('result');
    const getLinkButton = document.getElementById('get-link-button');
    const countdownElement = document.getElementById('countdown');
    const timerElement = document.getElementById('timer');
    resultElement.innerText = '';
    getLinkButton.style.display = 'none';
    countdownElement.style.display = 'none';

    const response = grecaptcha.getResponse();
    if (!response) {
        resultElement.innerText = 'Please complete the CAPTCHA';
        resultElement.className = 'error';
        return;
    }

    console.log('Sending verification request...');
    fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 'g-recaptcha-response': response })
    })
    .then(res => res.json())
    .then(data => {
        console.log('Response from server:', data);
        resultElement.innerText = data.message;
        resultElement.className = data.success ? 'success' : 'error';

        if (data.success) {
            console.log('Verification successful, redirecting...');
            setTimeout(() => {
                if (data.redirectUrl) {
                    window.location.href = data.redirectUrl;
                }
            }, 2000);
            if (data.redirectUrl) {
                getLinkButton.style.display = 'block';
                getLinkButton.onclick = () => window.location.href = data.redirectUrl;
            }
        } else if (data.status === 429 && data.remainingTime) {
            console.log('Rate limit hit, starting countdown...', data.remainingTime);
            countdownElement.style.display = 'block';
            let remaining = data.remainingTime;
            timerElement.innerText = remaining;
            const interval = setInterval(() => {
                remaining--;
                timerElement.innerText = remaining;
                if (remaining <= 0) {
                    clearInterval(interval);
                    countdownElement.style.display = 'none';
                    resultElement.innerText = 'You can verify now.';
                    resultElement.className = '';
                    grecaptcha.reset();
                    console.log('Countdown finished, CAPTCHA reset.');
                }
            }, 1000);
        }
    })
    .catch(error => {
        console.error('Error during verification:', error);
        resultElement.innerText = 'Error verifying CAPTCHA';
        resultElement.className = 'error';
    });
}
