function submitForm() {
    const resultElement = document.getElementById('result');
    const getLinkButton = document.getElementById('get-link-button');
    resultElement.innerText = '';
    getLinkButton.style.display = 'none';

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
        }
    })
    .catch(error => {
        resultElement.innerText = 'Error verifying CAPTCHA';
        resultElement.className = 'error';
    });
}
