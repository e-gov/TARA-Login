(function () {
    var pollInterval = 1000;
    var isPolling = true;
    const LONGER_THAN_EXPECTED_DELAY_MS = 5000;
    const TIMEOUT = 20000;

    try {
        var value = document.body.getAttribute("data-sid-web2app-poll-interval");
        var number = new Number(value);

        if (number >= 100) {
            pollInterval = number;
        }
    } catch (e) {
    }

    setTimeout(stopPolling, TIMEOUT);

    function stopPolling() {
        isPolling = false;
    }

    const csrfToken = document.querySelector("input[name='_csrf']").getAttribute("value");
    // Get the callback URL parameters and include them in the following polling queries
    const callbackParams = new URLSearchParams(window.location.search);

    setTimeout(() => {
        document.querySelector("#sid-web2app-longer-expected-text").classList.remove('hidden');
    }, LONGER_THAN_EXPECTED_DELAY_MS);

    function checkAuthenticationStatus() {
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function () {
            if (this.readyState !== 4) {
                return;
            } else if (this.responseText === "" && isPolling) {
                setTimeout(checkAuthenticationStatus, pollInterval);
                return;
            }

            var pollResponse;
            try {
                pollResponse = JSON.parse(this.responseText);
            } catch (e) {
                if (isPolling) {
                    setTimeout(checkAuthenticationStatus, pollInterval);
                    return;
                } else {
                    document.querySelector(".c-tab-login__main").classList.add('hidden');
                    document.querySelector("#sid-web2app-loader").classList.add('hidden');
                    document.querySelector("#sid-error").classList.remove('hidden');
                    document.querySelector("#error-incident-number-wrapper").classList.add('hidden');
                    document.querySelector("#error-report-url").classList.add('hidden');
                    document.querySelector("#default-error-message").classList.remove('hidden');
                    return;
                }
            }

            if (this.status === 200 && pollResponse["status"] === 'COMPLETED') {
                var form = document.createElement("form");
                form.method = "POST";
                form.action = "/auth/accept";

                var input = document.createElement("input");
                input.setAttribute("type", "hidden");
                input.setAttribute("name", "_csrf");
                input.setAttribute("value", csrfToken);
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
            } else if (this.status === 200 && pollResponse["status"] === 'PENDING' && isPolling) {
                setTimeout(checkAuthenticationStatus, pollInterval);
            } else {
                document.querySelector(".c-tab-login__main").classList.add('hidden');
                document.querySelector("#sid-web2app-loader").classList.add('hidden');
                document.querySelector("#sid-error").classList.remove('hidden');
                
                if (pollResponse["message"]) {
                    document.querySelector("#error-message").innerHTML = pollResponse["message"];
                } else {
                    document.querySelector("#error-message").classList.add('hidden');
                    document.querySelector("#default-error-message").classList.remove('hidden');
                }

                if (pollResponse["reportable"]) {
                    var timeFormat = document.querySelector("#error-incident-time").getAttribute("data-time-format");
                    var formattedDateTimeWithOffset = formatDateTimeWithBrowserOffset(
                        pollResponse["timestamp"], timeFormat);

                    document.querySelector("#error-incident-number").innerHTML = pollResponse["incident_nr"];
                    document.querySelector("#error-incident-time").innerHTML = formattedDateTimeWithOffset;

                    var errorReportUrl = document.querySelector("#error-report-url").href;
                    errorReportUrl = errorReportUrl.replace("{1}", pollResponse["message"]);
                    errorReportUrl = errorReportUrl.replace("{2}", pollResponse["incident_nr"]);
                    document.querySelector("#error-report-url").href = errorReportUrl;

                    var errorReportNotification = document.querySelector("#error-report-notification").innerHTML;
                    errorReportNotification = errorReportNotification.replace("{1}", pollResponse["incident_nr"]);
                    document.querySelector("#error-report-notification").innerHTML = errorReportNotification;
                } else {
                    document.querySelector("#error-incident-number-wrapper").classList.add('hidden');
                    document.querySelector("#error-report-url").classList.add('hidden');
                }
            }
        };
        xhttp.open('GET', '/auth/sid/web2app/callback/poll?' + callbackParams.toString(), true);
        xhttp.setRequestHeader('Accept', 'application/json;charset=UTF-8');
        xhttp.send();
    }

    setTimeout(checkAuthenticationStatus, pollInterval);
})();
