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
            // Tự động redirect sau 2 giây với link từ server
            setTimeout(() => {
                if (data.redirectUrl) {
                    window.location.href = data.redirectUrl;
                }
            }, 2000);
            // Fallback: Hiển thị nút Get Link với link từ server
            if (data.redirectUrl) {
                getLinkButton.style.display = 'block';
                getLinkButton.onclick = () => window.location.href = data.redirectUrl;
            }
        } else if (data.status === 429 && data.remainingTime) {
            // Lưu thời gian kết thúc countdown vào localStorage
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
    const countdownElement = document.getElementById('countdown');
    const timerElement = document.getElementById('timer');
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
            startCountdown(remaining);
        } else {
            localStorage.removeItem('countdownEndTime');
            grecaptcha.reset();
        }
    }
});
