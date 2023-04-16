package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;
import lombok.Getter;
import lombok.NonNull;

public abstract class TaraException extends RuntimeException {

    @Getter
    private final ErrorCode errorCode;

    public TaraException(ErrorCode errorCode, String message) {
        this(errorCode, message, null);
    }

    public TaraException(@NonNull ErrorCode errorCode, String message, Exception exception) {
        super(message, exception);
        this.errorCode = errorCode;
    }
}
