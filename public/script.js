const resultElement = document.getElementById('result');
const captchaWrapper = document.getElementById('captcha-wrapper');
const getLinkButton = document.getElementById('get-link-button');
const countdownElement = document.getElementById('countdown');
const timerElement = document.getElementById('timer');

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
        body: JSON.stringify({ 'g-recaptcha-response': response })
    })
    .then(res => res.json())
    .then(data => {
        resultElement.innerText = data.message;
        resultElement.className = data.success ? 'success' : 'error';

        if (data.success) {
            // Ẩn CAPTCHA sau khi verify thành công
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
            // Chặn CAPTCHA và hiển thị countdown
            grecaptcha.reset();
            captchaWrapper.style.pointerEvents = 'none'; // Vô hiệu hóa CAPTCHA
            captchaWrapper.classList.add('hidden'); // Ẩn CAPTCHA khi bị chặn
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

// Hàm bắt đầu bộ đếm thời gian
function startCountdown(remaining) {
    countdownElement.style.display = 'block';
    timerElement.innerText = remaining;
    const interval = setInterval(() => {
        remaining--;
        timerElement.innerText = remaining;
        if (remaining <= 0) {
            clearInterval(interval);
            countdownElement.style.display = 'none';
            localStorage.removeItem('countdownEndTime');
            resultElement.innerText = 'You can verify now.';
            resultElement.className = '';
            captchaWrapper.classList.remove('hidden'); // Hiển thị lại CAPTCHA
            captchaWrapper.style.pointerEvents = 'auto'; // Kích hoạt lại CAPTCHA
            grecaptcha.reset(); // Reset CAPTCHA để verify lại
        }
    }, 1000);
}

// Kiểm tra countdown khi tải trang
document.addEventListener('DOMContentLoaded', () => {
    const endTime = localStorage.getItem('countdownEndTime');
    if (endTime) {
        let remaining = Math.ceil((endTime - Date.now()) / 1000);
        if (remaining > 0) {
            captchaWrapper.classList.add('hidden'); // Ẩn CAPTCHA khi còn thời gian chặn
            captchaWrapper.style.pointerEvents = 'none'; // Vô hiệu hóa CAPTCHA
            startCountdown(remaining);
        } else {
            localStorage.removeItem('countdownEndTime');
            captchaWrapper.classList.remove('hidden'); // Hiển thị lại CAPTCHA
            captchaWrapper.style.pointerEvents = 'auto'; // Kích hoạt lại CAPTCHA
            grecaptcha.reset();
        }
    }
});
