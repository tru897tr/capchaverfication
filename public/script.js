const resultElement = document.getElementById('result');
const captchaWrapper = document.getElementById('captcha-wrapper');
const getLinkButton = document.getElementById('get-link-button');
const countdownElement = document.getElementById('countdown');
const timerElement = document.getElementById('timer');
const csrfTokenInput = document.getElementById('csrf-token');
const footer = document.getElementById('footer');

// Lấy thông tin thiết bị chi tiết
function getDeviceInfo() {
    return {
        userAgent: navigator.userAgent,
        screenResolution: `${window.screen.width}x${window.screen.height}`,
        language: navigator.language,
        platform: navigator.platform,
        fingerprint: btoa(`${navigator.userAgent}${window.screen.width}${window.screen.height}${navigator.language}${navigator.platform}`).slice(0, 50)
    };
}

// Lấy Public IP
function getPublicIp() {
    console.log('Fetching public IP...');
    return fetch('https://api.ipify.org?format=json')
        .then(response => response.json())
        .then(data => {
            console.log('Public IP fetched:', data.ip);
            return data.ip;
        })
        .catch(error => {
            console.error('Error fetching public IP:', error);
            return 'Unable to fetch public IP';
        });
}

function displayIpInfo() {
    getPublicIp().then(publicIp => {
        const ipInfoDiv = document.createElement('div');
        ipInfoDiv.id = 'ip-info';
        ipInfoDiv.innerHTML = `<p>Public IP: ${publicIp}</p>`;
        footer.appendChild(ipInfoDiv);
        console.log('Public IP displayed:', publicIp);
    });
}

function getCsrfToken() {
    console.log('Fetching CSRF token...');
    const deviceInfo = getDeviceInfo();
    fetch('/get-csrf-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ deviceInfo, clientIp: '' })
    })
    .then(res => res.json())
    .then(data => {
        console.log('CSRF token fetched:', data.csrfToken);
        csrfTokenInput.value = data.csrfToken;
        if (data.status === 429 && data.remainingTime) {
            startCountdown(data.remainingTime);
            resultElement.innerText = `Rate limited, remaining time: ${data.remainingTime} seconds`;
            resultElement.className = 'error';
            captchaWrapper.classList.add('hidden');
            captchaWrapper.style.pointerEvents = 'none';
        }
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

    console.log('Sending verification request with reCAPTCHA response:', response);
    fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            'g-recaptcha-response': response,
            'csrf-token': csrfTokenInput.value,
            'clientIp': '',
            'clientDevice': navigator.userAgent,
            'deviceInfo': getDeviceInfo()
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
        if (remaining <= 0) {
            clearInterval(interval);
            countdownElement.style.display = 'none';
            resultElement.innerText = 'You can verify now.';
            resultElement.className = '';
            captchaWrapper.classList.remove('hidden');
            captchaWrapper.style.pointerEvents = 'auto';
            grecaptcha.reset();
            console.log('Countdown finished, CAPTCHA reset.');
        } else {
            remaining -= 1;
            timerElement.innerText = remaining;
        }
    }, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('Page loaded, initiating setup...');
    getCsrfToken();
    displayIpInfo();
});
