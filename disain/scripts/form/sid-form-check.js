(function () {
    var timeout = 5000;

    try {
        var value = document.body.getAttribute("data-check-form-refresh-rate");
        var number = new Number(value);

        if (number >= 100) {
            timeout = number;
        }
    } catch (e) {
    }

    setTimeout(stopPolling, 360000);

    function stopPolling() {
        clearInterval(interval);
    }

    const csrf_token = document.querySelector("input[name='_csrf']").getAttribute("value");

    const interval = setInterval(function () {
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function () {
            if (this.readyState !== 4) return;

            if (this.status == 200 && this.responseText == '{"status":"COMPLETED"}') {
                clearInterval(interval);
                var form = document.createElement("form");
                form.method = "POST";
                form.action = "/auth/accept";

                var input = document.createElement("input");
                input.setAttribute("type", "hidden");
                input.setAttribute("name", "_csrf");
                input.setAttribute("value", csrf_token);
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
            } else if (this.status == 200 && this.responseText == '{"status":"PENDING"}') {
                console.log(this.responseText);
                return;
            } else {
                if (this.getResponseHeader('content-type') == "text/html;charset=UTF-8") {
                    clearInterval(interval);
                    document.write(this.responseText);
                }
            }
        };
        xhttp.open('GET', '/auth/sid/poll', true);
        xhttp.setRequestHeader('Accept', 'text/html;charset=UTF-8');
        xhttp.send();

    }, timeout);
})();
