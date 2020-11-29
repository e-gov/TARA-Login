package ee.ria.taraauthserver.error.Exceptions;

import ee.ria.taraauthserver.error.ErrorTranslationCodes;
import lombok.Getter;

public abstract class TaraException extends RuntimeException {

    @Getter
    private ErrorTranslationCodes messageCode;

    public TaraException(ErrorTranslationCodes messageCode, String debugMessage) {
        this(messageCode, debugMessage, null);
    }

    public TaraException(ErrorTranslationCodes messageCode, String debugMessage, Exception exception) {
        super(debugMessage, exception);
        this.messageCode = messageCode;
    }

}
