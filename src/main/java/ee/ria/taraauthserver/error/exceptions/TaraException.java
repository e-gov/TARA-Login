package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorTranslationCodes;
import lombok.Getter;

public abstract class TaraException extends RuntimeException {

    @Getter
    private final ErrorTranslationCodes messageCode;

    public TaraException(ErrorTranslationCodes messageCode, String debugMessage) {
        this(messageCode, debugMessage, null);
    }

    public TaraException(ErrorTranslationCodes messageCode, String debugMessage, Exception exception) {
        super(debugMessage, exception);
        this.messageCode = messageCode;
    }

}
