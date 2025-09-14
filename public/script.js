const resultElement = document.getElementById('result');
const captchaWrapper = document.getElementById('captcha-wrapper');
const getLinkButton = document.getElementById('get-link-button');
const countdownElement = document.getElementById('countdown');
const timerElement = document.getElementById('timer');
const csrfTokenInput = document.getElementById('csrf-token');
const footer = document.getElementById('footer');

// Lấy IP hiện tại
function getClientIp() {
    return window.location.hostname === 'localhost' ? '127.0.0.1' : '';
}

function getPublicIp() {
    return fetch('https://api.ipify.org?format=json')
        .then(response => response.json())
        .then(data => data.ip)
        .catch(error => {
            console.error('Error fetching public IP:', error);
            return 'Unable to fetch public IP';
        });
}

function displayIpInfo() {
    const privateIp = getClientIp();
    getPublicIp().then(publicIp => {
        const ipInfoDiv = document.createElement('div');
        ipInfoDiv.id = 'ip-info';
        ipInfoDiv.innerHTML = `
            <p>Private IP: ${privateIp}</p>
            <p>Public IP: ${publicIp}</p>
            <p>Device: ${navigator.userAgent}</p>
            <p>Time: ${new Date().toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' })}</p>
        `;
        footer.appendChild(ipInfoDiv);
        console.log('IP Info displayed:', { privateIp, publicIp });
    });
}

function getCsrfToken() {
    fetch('/get-csrf-token', { credentials: 'include' })
        .then(res => res.json())
        .then(data => {
            console.log('CSRF token fetched:', data.csrfToken);
            csrfTokenInput.value = data.csrfToken;
        })
        .catch(error => console.error('Error fetching CSRF token:', error));
}

function submitForm() {
    console.log('Submitting form...');
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
            'csrf-token': csrfTokenInput.value,
            'clientIp': getClientIp(),
            'clientDevice': navigator.userAgent
        })
    })
    .then(res => res.json())
    .then(data => {
        console.log('Server response:', data);
        resultElement.innerText = data.message;
        resultElement.className = data.success ? 'success' : 'error';

        if (data.success && data.redirectUrl) {
            console.log('Verification successful, redirect URL received:', data.redirectUrl);
            captchaWrapper.classList.add('hidden');
            setTimeout(() => {
                window.location.href = data.redirectUrl;
            }, 2000);
            getLinkButton.style.display = 'block';
            getLinkButton.onclick = () => window.location.href = data.redirectUrl;
        } else if (data.status === 429 && data.remainingTime) {
            console.log('Rate limit hit, remaining time:', data.remainingTime);
            grecaptcha.reset();
            captchaWrapper.style.pointerEvents = 'none';
            captchaWrapper.classList.add('hidden');
            const endTime = Date.now() + data.remainingTime * 1000;
            localStorage.setItem('countdownEndTime', endTime);
            startCountdown(data.remainingTime);
        }
    })
    .catch(error => {
        console.error('Error during verification:', error);
        resultElement.innerText = 'Error verifying CAPTCHA';
        resultElement.className = 'error';
    });
}

function startCountdown(remaining) {
    console.log('Starting countdown with remaining:', remaining);
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
            console.log('Countdown finished, CAPTCHA reset.');
        }
    }, 1000);
}

function checkRateLimit() {
    console.log('Checking rate limit...');
    const currentIp = getClientIp();
    console.log('Current IP:', currentIp);

    fetch('/check-rate-limit', { credentials: 'include' })
        .then(res => res.json())
        .then(data => {
            console.log('Rate limit check response:', data);
            if (data.status === 429 && data.remainingTime) {
                captchaWrapper.classList.add('hidden');
                captchaWrapper.style.pointerEvents = 'none';
                localStorage.setItem('countdownEndTime', Date.now() + data.remainingTime * 1000);
                startCountdown(data.remainingTime);
                resultElement.innerText = `Rate limited, remaining time: ${data.remainingTime} seconds`;
                resultElement.className = 'error';
            } else {
                // Xóa trạng thái cũ nếu IP thay đổi hoặc không bị limit
                const storedEndTime = localStorage.getItem('countdownEndTime');
                if (storedEndTime) {
                    localStorage.removeItem('countdownEndTime');
                    console.log('Cleared old countdown due to IP change or no limit.');
                }
                captchaWrapper.classList.remove('hidden');
                captchaWrapper.style.pointerEvents = 'auto';
                grecaptcha.reset();
                resultElement.innerText = '';
                resultElement.className = '';
            }
        })
        .catch(error => console.error('Error checking rate limit:', error));
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('Page loaded, initiating setup...');
    getCsrfToken();
    checkRateLimit();
    displayIpInfo(); // Hiển thị IP khi tải trang
});
