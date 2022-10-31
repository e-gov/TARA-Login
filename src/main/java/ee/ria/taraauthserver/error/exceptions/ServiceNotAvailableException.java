package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class ServiceNotAvailableException extends TaraException {

    public ServiceNotAvailableException(ErrorCode messageCode, String message, Exception exception) {
        super(messageCode, message, exception, null);
    }
}
