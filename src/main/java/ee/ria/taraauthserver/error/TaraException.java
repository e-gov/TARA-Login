package ee.ria.taraauthserver.error;

import lombok.Getter;

public abstract class TaraException extends RuntimeException {

    @Getter
    private ErrorMessages messageCode;

    public TaraException(ErrorMessages messageCode, String debugMessage) {
        this(messageCode, debugMessage, null);
    }

    public TaraException(ErrorMessages messageCode, String debugMessage, Exception exception) {
        super(debugMessage, exception);
        this.messageCode = messageCode;
    }

}
