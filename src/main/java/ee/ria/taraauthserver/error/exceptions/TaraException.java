package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;
import lombok.Getter;

public abstract class TaraException extends RuntimeException {

    @Getter
    private final String[] errorCodeMessageParameters;

    @Getter
    private final ErrorCode errorCode;

    public TaraException(ErrorCode errorCode, String message, Exception exception, String[] errorCodeMessageParameters) {
        super(message, exception);
        this.errorCode = errorCode;
        this.errorCodeMessageParameters = errorCodeMessageParameters;
    }
}
