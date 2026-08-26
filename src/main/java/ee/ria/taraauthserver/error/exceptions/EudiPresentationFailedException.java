package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class EudiPresentationFailedException extends TaraException {

    public EudiPresentationFailedException(ErrorCode errorCode, String message) {
        super(errorCode, message, null, null);
    }

}
