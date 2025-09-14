const resultElement = document.getElementById('result');
const captchaWrapper = document.getElementById('captcha-wrapper');
const getLinkButton = document.getElementById('get-link-button');
const countdownElement = document.getElementById('countdown');
const timerElement = document.getElementById('timer');
const csrfTokenInput = document.getElementById('csrf-token');
const footer = document.getElementById('footer');
const thumbnailElement = document.getElementById('thumbnail');

let recaptchaWidgetId = null;

function onRecaptchaLoad() {
    recaptchaWidgetId = grecaptcha.render('captcha-wrapper', {
        'sitekey': '6LfjhMYrAAAAAOfbm1shxCTML0WY5_HyJNAbnQBF',
        'callback': submitForm
    });
}

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
    return fetch('https://api.ipify.org?format=json')
        .then(response => response.json())
        .then(data => data.ip)
        .catch(() => 'Unable to fetch public IP');
}

function displayIpInfo() {
    getPublicIp().then(publicIp => {
        const ipInfoDiv = document.createElement('div');
        ipInfoDiv.id = 'ip-info';
        ipInfoDiv.innerHTML = `<p>Public IP: ${publicIp}</p>`;
        footer.appendChild(ipInfoDiv);
    });
}

// Hiển thị thumbnail
function displayThumbnail() {
    const thumbnailUrl = 'https://i.postimg.cc/d0gnh6pC/file-00000000f068622f96c3719d9e159475.png';
    thumbnailElement.src = thumbnailUrl;
    thumbnailElement.style.display = 'block';
}

function getCsrfToken() {
    const deviceInfo = getDeviceInfo();
    fetch('/get-csrf-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ deviceInfo, clientIp: '' })
    })
    .then(res => res.json())
    .then(data => {
        csrfTokenInput.value = data.csrfToken;
        if (data.status === 429 && data.remainingTime) {
            startCountdown(data.remainingTime);
            resultElement.innerText = `Rate limited, remaining time: ${data.remainingTime} seconds`;
            resultElement.className = 'error';
            captchaWrapper.classList.add('hidden');
            captchaWrapper.style.pointerEvents = 'none';
        } else {
            if (recaptchaWidgetId) grecaptcha.reset(recaptchaWidgetId);
            captchaWrapper.classList.remove('hidden');
            captchaWrapper.style.pointerEvents = 'auto';
            resultElement.innerText = '';
            resultElement.className = '';
        }
    })
    .catch(() => {
        resultElement.innerText = 'Error loading page';
        resultElement.className = 'error';
    });
}

function submitForm() {
    resultElement.innerText = '';
    getLinkButton.style.display = 'none';
    countdownElement.style.display = 'none';

    const response = grecaptcha.getResponse(recaptchaWidgetId);
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
            'clientIp': '',
            'clientDevice': navigator.userAgent,
            'deviceInfo': getDeviceInfo()
        })
    })
    .then(res => res.json())
    .then(data => {
        resultElement.innerText = data.message;
        resultElement.className = data.success ? 'success' : 'error';

        if (data.success && data.redirectUrl) {
            captchaWrapper.classList.add('hidden');
            setTimeout(() => {
                window.location.href = data.redirectUrl;
            }, 2000);
            getLinkButton.style.display = 'block';
            getLinkButton.onclick = () => window.location.href = data.redirectUrl;
        } else if (data.status === 429 && data.remainingTime) {
            grecaptcha.reset(recaptchaWidgetId);
            captchaWrapper.style.pointerEvents = 'none';
            captchaWrapper.classList.add('hidden');
            startCountdown(data.remainingTime);
        }
    })
    .catch(() => {
        resultElement.innerText = 'Error verifying CAPTCHA';
        resultElement.className = 'error';
    });
}

function startCountdown(remaining) {
    countdownElement.style.display = 'block';
    timerElement.innerText = remaining;
    const interval = setInterval(() => {
        if (remaining <= 0) {
            clearInterval(interval);
            countdownElement.style.display = 'none';
            getCsrfToken(); // Làm mới trạng thái từ server
        } else {
            remaining -= 1;
            timerElement.innerText = remaining;
        }
    }, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
    getCsrfToken();
    displayIpInfo();
    displayThumbnail(); // Hiển thị thumbnail khi trang tải
    // Retry if reCAPTCHA fails to load
    setTimeout(() => {
        if (!recaptchaWidgetId && typeof grecaptcha !== 'undefined') {
            onRecaptchaLoad();
        }
    }, 2000);
});
