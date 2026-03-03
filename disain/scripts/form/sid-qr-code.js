(function () {

    const POLL_INTERVAL_MS = 1000;
    const RETRYABLE_HTTP_STATUS_CODES = new Set([408, 502, 503, 504]);
    const MAX_RETRY_DURATION_MS = 30000;
    const MAX_POLL_DURATION_MS = 300000;
    /* QR codes expire after a certain amount of time, scanning such QR codes with Smart-ID app will fail. The timeout
    *  is not documented, so we have to use our best guess. */
    const QR_CODE_MAX_AGE_MS = 5000;

    const csrfToken = document.querySelector('meta[name="_csrf"]').content;
    const qrCodeEl = document.getElementById('sidQrCode');

    const pollSessionStartMs = Date.now();
    let firstRetryMs = null;
    let qrCodeExpirationTimeout = null;
    let pollAbortController = new AbortController();

    function createQrCodePromise(deviceLink) {
        /* QR code version 11 with error correction level LOW can fit up to 321 bytes of data. The example device
         * link provided on https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/dynamic_link_flows.html#_qr
         * is 213 characters long, which leaves us more than a 50% buffer. */
        return QRCode.toString(deviceLink, {
            version: 11,
            errorCorrectionLevel: 'low',
            margin: 1,
            scale: 1
        });
    }

    function pollStatus() {
        return fetch('/auth/sid/qr-code/poll', {
            headers: {
                'Accept': 'application/json;charset=UTF-8'
            },
            signal: AbortSignal.any([
                pollAbortController.signal,
                AbortSignal.timeout(10_000)
            ]),
            credentials: 'include'
        });
    }

    function scheduleNextPoll(pollStartMs) {
        const pollDurationMs = Date.now() - pollStartMs;
        setTimeout(doPoll, Math.max(0, POLL_INTERVAL_MS - pollDurationMs));
    }

    function scheduleRetry(pollStartMs) {
        const now = Date.now();
        if (firstRetryMs === null) {
            firstRetryMs = now;
        }
        if (now - firstRetryMs >= MAX_RETRY_DURATION_MS) {
            setErrorState({});
            return;
        }
        scheduleNextPoll(pollStartMs);
    }

    function showQrCode(qrCodeHtml) {
        qrCodeEl.innerHTML = qrCodeHtml;
        if (qrCodeExpirationTimeout != null) {
            clearTimeout(qrCodeExpirationTimeout);
        }
        qrCodeExpirationTimeout = setTimeout(showLoader, QR_CODE_MAX_AGE_MS);
    }

    function setErrorState(error) {
        pollAbortController.abort();
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

    async function doPoll() {
        if (pollAbortController.signal.aborted) {
            return;
        }
        if (Date.now() - pollSessionStartMs >= MAX_POLL_DURATION_MS) {
            setErrorState({});
            return;
        }
        const pollStartMs = Date.now();
        let response;
        try {
            response = await pollStatus();
        } catch (fetchError) {
            if (pollAbortController.signal.aborted) {
                return;
            }
            // Network errors and request timeouts are treated as transient — retry within the allowed window.
            scheduleRetry(pollStartMs);
            return;
        }

        if (!response.ok) {
            if (RETRYABLE_HTTP_STATUS_CODES.has(response.status)) {
                scheduleRetry(pollStartMs);
            } else {
                const errorBody = await response.json().catch(_ => ({}));
                setErrorState(errorBody);
            }
            return;
        }

        try {
            const responseBody = await response.json();
            switch (responseBody.status) {
                case 'PENDING': {
                    const deviceLink = responseBody.deviceLink;
                    if (deviceLink == null) {
                        break;
                    }
                    const qrCodeHtml = await createQrCodePromise(deviceLink);
                    showQrCode(qrCodeHtml);
                    break;
                }
                case 'COMPLETED':
                    acceptAuthentication();
                    return;
                case 'FAILED':
                default:
                    setErrorState(responseBody);
                    return;
            }
        } catch (error) {
            // If any kind of unexpected JS Error is thrown, we don't want to display the technical message.
            setErrorState({});
            return;
        }
        firstRetryMs = null;
        scheduleNextPoll(pollStartMs);
    }

    function hideEl(el) {
        el.classList.add('hidden');
    }

    function showEl(el) {
        el.classList.remove('hidden');
    }

    window.addEventListener('beforeunload', function () {
        pollAbortController.abort();
    });

    doPoll();

})();
