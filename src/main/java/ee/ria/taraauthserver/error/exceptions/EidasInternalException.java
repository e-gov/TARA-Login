package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class EidasInternalException extends TaraException {

    public EidasInternalException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public EidasInternalException(ErrorCode errorCode, String message, Exception exception) {
        super(errorCode, message, exception);
    }
}
