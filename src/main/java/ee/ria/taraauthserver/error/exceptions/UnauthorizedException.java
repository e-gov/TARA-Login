package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class UnauthorizedException extends TaraException {

    public UnauthorizedException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public UnauthorizedException(ErrorCode errorCode, String message, Exception exception) {
        super(errorCode, message, exception);
    }
}
