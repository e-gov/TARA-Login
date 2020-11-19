(function() {
    var timeout = 5000;

    try {
        var value = document.body.getAttribute("data-check-form-refresh-rate");
        var number = new Number(value);

        if (number >= 100) {
            timeout = number;
        }
    } catch (e) {}

    setTimeout(stopPolling, 360000);

    function stopPolling() {
        clearInterval(interval);
    }

    const interval = setInterval(function() {

    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (this.readyState !== 4) return;
        console.log(this.responseText);

        if (this.responseText == '{"status":"COMPLETED"}') {
            clearInterval(interval);
            window.location.pathname = '/auth/accept'
        }
        if (this.getResponseHeader('content-type') == "text/html;charset=UTF-8") {
            clearInterval(interval);
            document.write(this.responseText);
        }

        if (this.status != 200) {
            clearInterval(interval);
        }

    };
       xhttp.open('GET', '/auth/mid/poll', true);
       xhttp.setRequestHeader('Content-type', 'application/json;charset=UTF-8');
       xhttp.send();

     }, timeout);
})();
