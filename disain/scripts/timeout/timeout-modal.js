jQuery(function ($) {
    let timeoutTimestamp;

    addListeners();
    addLoginAuthFlowTimeout();

    function addLoginAuthFlowTimeout() {
        let secondsToTimeout = $('#auth-flow-timeout-timer').get(0).getAttribute('data-seconds-to-timeout');
        if (secondsToTimeout == null) {
            return null;
        }
        secondsToTimeout = parseInt(secondsToTimeout,10);

        let currentTimestamp = getCurrentTimeStampInSeconds();
        timeoutTimestamp = currentTimestamp + secondsToTimeout;

        const timeouts = [
            {threshold: 60},   //1 minute
            {threshold: 300},  //5 minutes
        ];

        timeouts.forEach(({threshold}) => {
            const timeDifference = secondsToTimeout - threshold;
            if (timeDifference > 0) {
                setTimeout(() => displayTimeoutModal(threshold), timeDifference * 1000);
            }
        });

        // Always schedule the throwTimeoutError
        setTimeout(throwTimeoutError, secondsToTimeout * 1000);
    }

    function throwTimeoutError(){
        if($('#id-card-wait').hasClass('hidden')){
            window.location.href = '/error-handler?error_code=auth_flow_timeout';
        }else{
            setTimeout(throwTimeoutError, 1000); //extend session 1 second and try again
        }
    }

    function displayTimeoutModal( secondsToTimeout){
        let authFlowTimeout = document.getElementById('auth-flow-timeout');
        if(authFlowTimeout.classList.contains('show') || !$('#id-card-wait').hasClass('hidden')){
            return null;
        }

        incrementAuthFlowTimeoutTimer(secondsToTimeout);
        --secondsToTimeout;
        authFlowTimeout.classList.add('show');
        authFlowTimeout.setAttribute('aria-hidden', 'false');
        authFlowTimeout.focus();

        let intervalId = setInterval(function() {
            if (!authFlowTimeout.classList.contains('show') || secondsToTimeout<=0) {
                clearInterval(intervalId);
            }
            incrementAuthFlowTimeoutTimer(secondsToTimeout);
            secondsToTimeout = timeoutTimestamp - getCurrentTimeStampInSeconds();
        }, 1000);
    }

    function incrementAuthFlowTimeoutTimer(secondsToTimeout){
        let minutes = String(Math.floor(secondsToTimeout / 60));
        let seconds = String(secondsToTimeout % 60).padStart(2, '0');

        $('#auth-flow-timeout-timer').text(`${minutes}:${seconds}`);
        if (seconds==='00') {
            $('#auth-flow-timeout-minute-counter').text(minutes);
        }
    }

    function addListeners(){
        $('.modal .close,.modal .accept').click(hideModal);
    }

    function hideModal(){
        $(this).closest('.modal').removeClass('show').attr('aria-hidden', 'true');
    }

    function getCurrentTimeStampInSeconds() {
        return Math.floor(Date.now() / 1000);
    }
});
