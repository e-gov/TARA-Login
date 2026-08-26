(function () {

    const POLL_INTERVAL_MS = 1000;
    const REQUEST_TIMEOUT_MS = 10000;

    const waitEl = document.getElementById('eudiWeb2AppWait');
    const completedEl = document.getElementById('eudiWeb2AppCompleted');
    const endedEl = document.getElementById('eudiWeb2AppEnded');

    let stopped = false;
    let pollInFlight = false;
    let nextPollTimeout = null;

    function pollStatus() {
        return fetch('/auth/eudi/web2app/poll', {
            headers: {
                'Accept': 'application/json;charset=UTF-8'
            },
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
            credentials: 'include'
        });
    }

    function stopWithError(error) {
        stopped = true;
        window.showEudiError(error);
    }

    function stopWithMessage(messageEl) {
        stopped = true;
        waitEl.classList.add('hidden');
        messageEl.classList.remove('hidden');
    }

    /* At most one request at a time: a poll asked for while one is in flight is left to the next one it schedules. */
    async function doPoll() {
        if (stopped || pollInFlight) {
            return;
        }
        pollInFlight = true;
        const pollStartMs = Date.now();
        try {
            const response = await pollStatus();
            const body = await response.json();
            if (!response.ok) {
                stopWithError(body != null && typeof body === 'object' ? body : {});
                return;
            }
            if (body?.status === 'PENDING') {
                const pollDurationMs = Date.now() - pollStartMs;
                nextPollTimeout = setTimeout(doPoll, Math.max(0, POLL_INTERVAL_MS - pollDurationMs));
            } else if (body?.status === 'COMPLETED') {
                stopWithMessage(completedEl);
            } else if (body?.status === 'ENDED') {
                stopWithMessage(endedEl);
            } else {
                stopWithError({});
            }
        } catch (error) {
            stopWithError({});
        } finally {
            pollInFlight = false;
        }
    }

    document.addEventListener('visibilitychange', function () {
        if (document.visibilityState !== 'visible' || stopped) {
            return;
        }
        clearTimeout(nextPollTimeout);
        doPoll();
    });

    doPoll();

})();
