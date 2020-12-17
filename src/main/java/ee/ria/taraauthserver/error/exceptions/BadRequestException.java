package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class BadRequestException extends TaraException {

    public BadRequestException(String message) {
        super(null, message);
    }

    public BadRequestException(ErrorCode errorCode, String message) {
        super(errorCode, message, null);
    }

    public BadRequestException(ErrorCode errorCode, String message, Exception exception) {
        super(errorCode, message, exception);
    }
}
