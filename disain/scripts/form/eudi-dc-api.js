(function () {

    const PROTOCOL = 'openid4vp-v1-signed';
    // Longer than the server's worst case, so that a login the server completes is not shown as failed.
    const REQUEST_TIMEOUT_MS = 60000;
    // The user closed the wallet dialog or no wallet answered: the user can try again.
    const DISMISSED_ERRORS = new Set(['NotAllowedError', 'AbortError']);

    const csrfToken = document.querySelector('meta[name="_csrf"]').content;
    const containerEl = document.getElementById('eudiDcApi');
    const buttonEl = document.getElementById('eudiDcApiButton');
    const requestObject = containerEl.getAttribute('data-request');

    function requestCredential() {
        return navigator.credentials.get({
            mediation: 'required',
            digital: {
                requests: [{
                    protocol: PROTOCOL,
                    data: {request: requestObject}
                }]
            }
        });
    }

    function postJson(path, body) {
        return fetch(path, {
            method: 'POST',
            headers: {
                'Accept': 'application/json;charset=UTF-8',
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': csrfToken
            },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
            credentials: 'include'
        });
    }

    // Browsers have returned the protocol response both as an object and as a JSON string.
    function walletResponseData(credential) {
        const data = credential.data;
        return typeof data === 'string' ? JSON.parse(data) : data;
    }

    async function presentCredential() {
        buttonEl.disabled = true;
        let data;
        try {
            data = walletResponseData(await requestCredential());
        } catch (error) {
            if (DISMISSED_ERRORS.has(error.name)) {
                buttonEl.disabled = false;
            } else {
                await reportCredentialError(error);
            }
            return;
        }

        let response;
        try {
            response = await postJson('/auth/eudi/dc-api/response', data);
        } catch (error) {
            showEudiError({});
            return;
        }
        if (response.ok) {
            acceptAuthentication();
            return;
        }
        const errorBody = await response.json().catch(_ => ({}));
        showEudiError(errorBody);
    }

    // The server never answers 200: it ends the login and returns the error to show.
    async function reportCredentialError(error) {
        let errorBody = {};
        try {
            const response = await postJson('/auth/eudi/dc-api/error', {name: error.name, message: error.message});
            errorBody = await response.json();
        } catch (_) {
            // Shown as the generic error.
        }
        showEudiError(errorBody);
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
        formEl.style.display = "none";
        document.body.appendChild(formEl);
        formEl.submit();
    }

    buttonEl.addEventListener('click', presentCredential);

})();
