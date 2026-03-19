(function () {
    let pollIntervalMs;
    // In some rare cases an error might become visible for a short time after user manually cancels polling.
    // Checking this variable can be used as a workaround to hide that error.
    let cancelled = false;
    let sessionToken = "";

    $("#sidWeb2AppLink").on("click", function (e) {
        // Workaround for Firefox: make request to /init endpoint without making the browser think we want to navigate
        // away from the current page. If we would initiate the request using a common HTML link, then Firefox would stop
        // setTimeout() timers required for polling.
        e.preventDefault();
        initAuthenticationAndStartPolling();
        hide(".c-layout--full > .container");
        hide(".link-back-mobile");
        show("#smart-id-web2app-wait");
        show("#sid-mobile-tab-context");
    });

    $("#sid-web2app-wait-login form").on("submit", function (e) {
        cancelled = true;
    });

    function setupErrorBackLinkHandler() {
        const errorBackLink = document.querySelector("#login-form-error .link-back a");
        if (errorBackLink) {
            errorBackLink.addEventListener("click", function() {
                hide("#sid-mobile-tab-context");
            }, { once: true });
        }
    }

    function initAuthenticationAndStartPolling() {
        const csrfToken = document.querySelector("input[name='_csrf']").getAttribute("value");
        fetch("/auth/sid/web2app/init", {
                method: "POST",
                body: new URLSearchParams({_csrf: csrfToken}),
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Failed to start Smart-ID authentication: TARA returned error ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                parseSessionTokenFromDeviceLink(data.deviceLink);
                startPolling();
                window.location.href = data.deviceLink;
            })
            .catch(err => {
                if (cancelled) {
                    return;
                }
                console.error(err.message);
                hide("#smart-id-web2app-wait");
                show("#sid-mobile-tab-context");
                setupErrorBackLinkHandler();
                show("#login-form-error");
                document.querySelector("#error-incident-number-wrapper").classList.add('hidden');
                document.querySelector("#error-report-url").classList.add('hidden');
                hide("#error-message");
                show("#default-error-message");
            });
    }

    function startPolling() {
        pollIntervalMs = parseInt($("#sidWeb2AppLinkContainer").attr("data-sid-web2app-poll-interval"));
        setTimeout(checkAuthenticationStatus, pollIntervalMs);
    }

    function parseSessionTokenFromDeviceLink(deviceLink) {
        const url = new URL(deviceLink);
        sessionToken = url.searchParams.get("sessionToken");
    }

    function show(selector) {
        const element = $(selector);
        element.attr('aria-hidden', 'false');
        element.removeClass('hidden');
    }

    function hide(selector) {
        const element = $(selector);
        element.attr('aria-hidden', 'true');
        element.addClass('hidden');
    }

    function checkAuthenticationStatus() {
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function () {
            if (this.readyState !== 4 || cancelled) {
                return;
            }

            var pollResponse;
            try {
                pollResponse = JSON.parse(this.responseText);
            } catch (e) {
                hide("#smart-id-web2app-wait");
                show("#sid-mobile-tab-context");
                show("#login-form-error");
                document.querySelector(".c-tab-login__main").classList.add('hidden');
                document.querySelector("#login-form-error").classList.remove('hidden');
                document.querySelector("#error-incident-number-wrapper").classList.add('hidden');
                document.querySelector("#error-report-url").classList.add('hidden');
                document.querySelector("#default-error-message").classList.remove('hidden');
                return;
            }

            if (this.status === 200 && pollResponse["status"] === 'COMPLETED') {
                $("#sid-web2app-wait-login").hide();
                $("#sid-web2app-login-success").show();
            } else if (this.status === 200 && pollResponse["status"] === 'PENDING') {
                setTimeout(checkAuthenticationStatus, pollIntervalMs);
            } else { // Failure
                hide("#smart-id-web2app-wait");
                show("#sid-mobile-tab-context");
                setupErrorBackLinkHandler();
                show("#login-form-error");
                document.querySelector("#error-message").innerHTML = pollResponse["message"];

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
                // Error message appears on top of the page and might not be visible to the user without scrolling to top
                window.scrollTo(0, 0);
            }
        };
        xhttp.open('GET', `/auth/sid/web2app/poll?sessionToken=${encodeURIComponent(sessionToken)}`, true);
        xhttp.setRequestHeader('Accept', 'application/json;charset=UTF-8');
        xhttp.send();
    }
})();
