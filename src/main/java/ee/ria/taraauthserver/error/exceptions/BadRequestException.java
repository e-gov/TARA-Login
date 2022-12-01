package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class BadRequestException extends TaraException {

    public BadRequestException(ErrorCode errorCode, String message) {
        super(errorCode, message, null, null);
    }

    public BadRequestException(ErrorCode errorCode, String message, Exception exception) {
        super(errorCode, message, exception, null);
    }

    public BadRequestException(ErrorCode errorCode, String message, String[] errorCodeMessageParameters) {
        super(errorCode, message, null, errorCodeMessageParameters);
    }
}
