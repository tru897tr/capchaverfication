const resultElement = document.getElementById('result');
const captchaWrapper = document.getElementById('captcha-wrapper');
const getLinkButton = document.getElementById('get-link-button');
const countdownElement = document.getElementById('countdown');
const timerElement = document.getElementById('timer');
const csrfTokenInput = document.getElementById('csrf-token');

function getCsrfToken() {
    fetch('/get-csrf-token', { credentials: 'include' })
        .then(res => res.json())
        .then(data => {
            csrfTokenInput.value = data.csrfToken;
        })
        .catch(error => console.error('Error fetching CSRF token:', error));
}

function submitForm() {
    resultElement.innerText = '';
    getLinkButton.style.display = 'none';
    countdownElement.style.display = 'none';

    const response = grecaptcha.getResponse();
    if (!response) {
        resultElement.innerText = 'Please complete the CAPTCHA';
        resultElement.className = 'error';
        return;
    }

    fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            'g-recaptcha-response': response,
            'csrf-token': csrfTokenInput.value
        })
    })
    .then(res => res.json())
    .then(data => {
        resultElement.innerText = data.message;
        resultElement.className = data.success ? 'success' : 'error';

        if (data.success) {
            captchaWrapper.classList.add('hidden');
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
            grecaptcha.reset();
            captchaWrapper.style.pointerEvents = 'none';
            captchaWrapper.classList.add('hidden');
            const endTime = Date.now() + data.remainingTime * 1000;
            localStorage.setItem('countdownEndTime', endTime);
            startCountdown(data.remainingTime);
        }
    })
    .catch(error => {
        resultElement.innerText = 'Error verifying CAPTCHA';
        resultElement.className = 'error';
    });
}

function startCountdown(remaining) {
    countdownElement.style.display = 'block';
    timerElement.innerText = remaining;
    const interval = setInterval(() => {
        remaining = Math.max(0, Math.ceil((localStorage.getItem('countdownEndTime') - Date.now()) / 1000));
        timerElement.innerText = remaining;
        if (remaining <= 0) {
            clearInterval(interval);
            countdownElement.style.display = 'none';
            localStorage.removeItem('countdownEndTime');
            resultElement.innerText = 'You can verify now.';
            resultElement.className = '';
            captchaWrapper.classList.remove('hidden');
            captchaWrapper.style.pointerEvents = 'auto';
            grecaptcha.reset();
        }
    }, 1000);
}

function checkRateLimit() {
    fetch('/check-rate-limit', { credentials: 'include' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 429 && data.remainingTime) {
                captchaWrapper.classList.add('hidden');
                captchaWrapper.style.pointerEvents = 'none';
                localStorage.setItem('countdownEndTime', Date.now() + data.remainingTime * 1000);
                startCountdown(data.remainingTime);
            }
        })
        .catch(error => console.error('Error checking rate limit:', error));
}

document.addEventListener('DOMContentLoaded', () => {
    getCsrfToken();
    checkRateLimit(); // Kiểm tra trạng thái rate limit khi tải trang
    const endTime = localStorage.getItem('countdownEndTime');
    if (endTime) {
        let remaining = Math.ceil((endTime - Date.now()) / 1000);
        if (remaining > 0) {
            captchaWrapper.classList.add('hidden');
            captchaWrapper.style.pointerEvents = 'none';
            startCountdown(remaining);
        } else {
            localStorage.removeItem('countdownEndTime');
            captchaWrapper.classList.remove('hidden');
            captchaWrapper.style.pointerEvents = 'auto';
            grecaptcha.reset();
        }
    }
});
