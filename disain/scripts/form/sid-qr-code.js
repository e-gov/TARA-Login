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
        });
    }

    function showQrCode(qrCodeHtml) {
        qrCodeEl.innerHTML = qrCodeHtml;
        if (qrCodeExpirationTimeout != null) {
            clearTimeout(qrCodeExpirationTimeout);
        }
        qrCodeExpirationTimeout = setTimeout(showLoader, QR_CODE_MAX_AGE_MS);
    }

    function showError(error) {
        hideEl(document.querySelector(".c-tab-login__main"));
        showEl(document.querySelector("#sid-error"));

        const errorMessageEl = document.querySelector("#error-message");
        const defaultErrorMessageEl = document.querySelector("#default-error-message");
        if (error.message != null) {
            hideEl(defaultErrorMessageEl);
            errorMessageEl.innerHTML = error.message;
            showEl(errorMessageEl);
        } else {
            showEl(defaultErrorMessageEl);
            hideEl(errorMessageEl);
        }

        const incidentNumberWrapperEl = document.querySelector("#error-incident-number-wrapper");
        const incidentNumberEl = document.querySelector("#error-incident-number");
        const incidentTimeEl = document.querySelector("#error-incident-time");
        const reportUrlEl = document.querySelector("#error-report-url");
        const reportNotificationEl = document.querySelector("#error-report-notification");
        if (error.reportable === true) {
            showEl(incidentNumberWrapperEl);
            showEl(reportUrlEl);
            incidentNumberEl.innerHTML = error.incident_nr;
            const timeFormat = incidentTimeEl.getAttribute("data-time-format");
            incidentTimeEl.innerHTML = formatDateTimeWithBrowserOffset(error.timestamp, timeFormat);
            reportUrlEl.href = reportUrlEl.href
                .replace('{1}', error.message)
                .replace('{2}', error.incident_nr);
            reportNotificationEl.innerHTML = reportNotificationEl.innerHTML
                .replace('{1}', error.incident_nr);
        } else {
            hideEl(incidentNumberWrapperEl);
            hideEl(reportUrlEl);
        }
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
        let pollingCancelled = false;
        pollStatus().then(function(response) {
            if (!response.ok) {
                throw new Error('Polling status returned HTTP error ' + response.status + ' ' + response.statusText);
            }
            return response.json();
        }).then(function(responseBody) {
            switch (responseBody.status) {
                case 'PENDING':
                    const deviceLink = responseBody.deviceLink;
                    if (deviceLink == null) {
                        return;
                    }
                    return createQrCodePromise(deviceLink).then(function (qrCodeHtml) {
                        showQrCode(qrCodeHtml);
                    });
                case 'COMPLETED':
                    pollingCancelled = true;
                    return acceptAuthentication();
                case 'FAILED':
                default:
                    pollingCancelled = true;
                    showError(responseBody);
                    return;
            }
        }).catch(function(error) {
            pollingCancelled = true;
            // If any kind of unexpected JS Error is thrown, we don't want to display the technical message.
            showError({});
        }).then(function () {
            if (pollingCancelled) {
                return;
            }
            const pollDurationMs = Date.now() - pollStartMs;
            setTimeout(doPoll, Math.max(0, POLL_INTERVAL_MS - pollDurationMs));
        })
    }

    function hideEl(el) {
        el.classList.add('hidden');
    }

    function showEl(el) {
        el.classList.remove('hidden');
    }

    doPoll();

})();


