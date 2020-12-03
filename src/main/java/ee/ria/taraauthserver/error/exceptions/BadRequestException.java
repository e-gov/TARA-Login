package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorTranslationCodes;

public class BadRequestException extends TaraException {

    public BadRequestException(String debugMessage) {
        super(null, debugMessage);
    }

    public BadRequestException(ErrorTranslationCodes messageCode, String debugMessage) {
        super(messageCode, debugMessage, null);
    }

    public BadRequestException(ErrorTranslationCodes messageCode, String debugMessage, Exception exception) {
        super(messageCode, debugMessage, exception);
    }
}
