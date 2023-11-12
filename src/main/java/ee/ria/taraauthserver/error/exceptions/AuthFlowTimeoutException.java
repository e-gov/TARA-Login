package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class AuthFlowTimeoutException extends TaraException {

    public AuthFlowTimeoutException(String message) {
        super(ErrorCode.AUTH_FLOW_TIMEOUT, message, null, null);
    }
}
