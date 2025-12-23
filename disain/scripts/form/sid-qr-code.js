(function () {

    const POLL_INTERVAL_MS = 1000;
    /* QR codes expire after a certain amount of time, scanning such QR codes with Smart-ID app will fail. The timeout
    *  is not documented, so we have to use our best guess. */
    const QR_CODE_MAX_AGE_MS = 5000;

    const qrCodeEl = document.getElementById('sidQrCode');

    function loadQrCodeHtml() {
        return fetch('/auth/sid/qr-code/poll', {
            headers: {
                'Accept': 'application/json;charset=UTF-8'
            }
        }).then(function (response) {
            return response.json();
        }).then(function (responseBody) {
            /* QR code version 11 with error correction level LOW can fit up to 321 bytes of data. The example device
             * link provided on https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/dynamic_link_flows.html#_qr
             * is 213 characters long, which leaves us more than a 50% buffer. */
            return QRCode.toString(responseBody.deviceLink, {
                version: 11,
                errorCorrectionLevel: 'low',
                margin: 0,
                scale: 1
            });
        });
    }

    let pollStartMs = 0;
    let qrCodeExpirationTimeout = null;

    function doPoll() {
        pollStartMs = Date.now();
        loadQrCodeHtml().then(function(qrCodeHtml) {
            qrCodeEl.innerHTML = qrCodeHtml;
            if (qrCodeExpirationTimeout != null) {
                clearTimeout(qrCodeExpirationTimeout);
            }
            qrCodeExpirationTimeout = setTimeout(showLoader, QR_CODE_MAX_AGE_MS);
        }).catch(function(error) {
            console.error('Failed to update Smart-ID device link QR code', error);
        }).then(function () {
            const pollDurationMs = Date.now() - pollStartMs;
            setTimeout(doPoll, Math.max(0, POLL_INTERVAL_MS - pollDurationMs));
        })
    }

    function showLoader() {
        qrCodeEl.innerHTML = '<div class="loadersmall"></div>';
    }

    doPoll();

})();


