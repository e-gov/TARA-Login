package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class VerificationException extends TaraException {

    public VerificationException(ErrorCode errorCode, String message) {
        super(errorCode, message, null, null);
    }

    public VerificationException(ErrorCode errorCode, String message, Exception exception) {
        super(errorCode, message, exception, null);
    }

    public VerificationException(ErrorCode errorCode, String message, String[] errorCodeMessageParameters) {
        super(errorCode, message, null, errorCodeMessageParameters);
    }
}
