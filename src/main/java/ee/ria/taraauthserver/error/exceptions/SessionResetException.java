package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class SessionResetException extends TaraException {

    public SessionResetException(String message) {
        super(ErrorCode.SESSION_STATE_INVALID, message, null, null);
    }
}
