(function () {

    // Fills the error fragment, including the incident number and the error report link of a reportable error.
    const REPORT_URL_PLACEHOLDERS = /\(([1-5])\)/g;
    const REPORT_NOTIFICATION_PLACEHOLDERS = /\{([12])\}/g;

    function showEudiError(error) {
        hideEl(document.querySelector('.c-tab-login__main'));
        showEl(document.querySelector('#eudi-error'));

        const errorMessageEl = document.querySelector('#error-message');
        const defaultErrorMessageEl = document.querySelector('#default-error-message');
        let shownMessageEl;
        if (error.message != null) {
            hideEl(defaultErrorMessageEl);
            errorMessageEl.innerHTML = error.message;
            showEl(errorMessageEl);
            shownMessageEl = errorMessageEl;
        } else {
            showEl(defaultErrorMessageEl);
            hideEl(errorMessageEl);
            shownMessageEl = defaultErrorMessageEl;
        }

        const incidentNumberWrapperEl = document.querySelector('#error-incident-number-wrapper');
        const reportUrlEl = document.querySelector('#error-report-url');
        if (error.reportable === true) {
            const incidentTimeEl = document.querySelector('#error-incident-time');
            const timeFormat = incidentTimeEl.getAttribute('data-time-format');
            incidentTimeEl.textContent = formatDateTimeWithBrowserOffset(error.timestamp, timeFormat);
            document.querySelector('#error-incident-number').textContent = error.incident_nr;
            fillErrorReport(reportUrlEl, shownMessageEl.textContent.trim(), error.incident_nr);
            showEl(incidentNumberWrapperEl);
            showEl(reportUrlEl);
        } else {
            hideEl(incidentNumberWrapperEl);
            hideEl(reportUrlEl);
        }
    }

    function fillErrorReport(reportUrlEl, plainTextMessage, incidentNumber) {
        const hostName = location.hostname;
        const reportUrlValues = {
            1: plainTextMessage,
            2: incidentNumber,
            3: navigator.platform,
            4: `${navigator.appCodeName}/${navigator.appVersion}`,
            5: hostName
        };
        const reportUrl = reportUrlEl.getAttribute('href')
            .replace(REPORT_URL_PLACEHOLDERS, (placeholder, index) => encodeURIComponent(reportUrlValues[index]));
        reportUrlEl.setAttribute('href', reportUrl);

        const reportNotificationValues = {1: incidentNumber, 2: hostName};
        const reportNotificationEl = document.querySelector('#error-report-notification');
        reportNotificationEl.textContent = reportNotificationEl.textContent
            .replace(REPORT_NOTIFICATION_PLACEHOLDERS, (placeholder, index) => reportNotificationValues[index]);
    }

    function hideEl(el) {
        el.classList.add('hidden');
    }

    function showEl(el) {
        el.classList.remove('hidden');
    }

    window.showEudiError = showEudiError;

})();
