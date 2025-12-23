(function () {

    const POLL_INTERVAL_MS = 1000;
    /* QR codes expire after a certain amount of time, scanning such QR codes with Smart-ID app will fail. The timeout
    *  is not documented, so we have to use our best guess. */
    const QR_CODE_MAX_AGE_MS = 5000;

    const csrfToken = document.querySelector('meta[name="_csrf"]').content;
    const qrCodeEl = document.getElementById('sidQrCode');

    let pollStartMs = 0;
    let qrCodeExpirationTimeout = null;

    function createQrCodePromise(deviceLink) {
        /* QR code version 11 with error correction level LOW can fit up to 321 bytes of data. The example device
         * link provided on https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/dynamic_link_flows.html#_qr
         * is 213 characters long, which leaves us more than a 50% buffer. */
        return QRCode.toString(deviceLink, {
            version: 11,
            errorCorrectionLevel: 'low',
            margin: 0,
            scale: 1
        });
    }

    function pollStatus() {
        return fetch('/auth/sid/qr-code/poll', {
            headers: {
                'Accept': 'application/json;charset=UTF-8'
            },
            credentials: 'include'
        }).then(function (response) {
            return response.json();
        });
    }

    function showQrCode(qrCodeHtml) {
        qrCodeEl.innerHTML = qrCodeHtml;
        if (qrCodeExpirationTimeout != null) {
            clearTimeout(qrCodeExpirationTimeout);
        }
        qrCodeExpirationTimeout = setTimeout(showLoader, QR_CODE_MAX_AGE_MS);
    }

    function acceptAuthentication() {
        const formEl = document.createElement("form");
        formEl.method = "POST";
        formEl.action = "/auth/accept";

        const csrfInputEl = document.createElement("input");
        csrfInputEl.setAttribute("type", "hidden");
        csrfInputEl.setAttribute("name", "_csrf");
        csrfInputEl.setAttribute("value", csrfToken);

        formEl.appendChild(csrfInputEl);
        formEl.style.display = "none"
        document.body.appendChild(formEl);
        formEl.submit();
    }

    function showLoader() {
        qrCodeEl.innerHTML = '<div class="loadersmall"></div>';
    }

    function doPoll() {
        pollStartMs = Date.now();
        pollStatus().then(function(response) {
            switch (response.status) {
                case "PENDING":
                    const deviceLink = response.deviceLink;
                    if (deviceLink == null) {
                        return;
                    }
                    return createQrCodePromise(deviceLink).then(function (qrCodeHtml) {
                        showQrCode(qrCodeHtml);
                    });
                case "COMPLETED":
                    return acceptAuthentication();
                case "FAILED":
                    //TODO (AUT-2500): Properly handle authentication failure
                    console.error('Smart-ID authentication failed');
                    return;
            }
        }).catch(function(error) {
            //TODO (AUT-2500): Properly handle polling errors
            console.error('Failed to update Smart-ID device link QR code', error);
        }).then(function () {
            const pollDurationMs = Date.now() - pollStartMs;
            setTimeout(doPoll, Math.max(0, POLL_INTERVAL_MS - pollDurationMs));
        })
    }

    doPoll();

})();


