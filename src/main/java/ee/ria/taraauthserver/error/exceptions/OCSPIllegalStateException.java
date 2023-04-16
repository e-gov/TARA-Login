package ee.ria.taraauthserver.error.exceptions;

import lombok.Getter;

@Getter
public class OCSPIllegalStateException extends IllegalStateException {
    private final String ocspUrl;

    public OCSPIllegalStateException(String message, String ocspUrl) {
        super(message);
        this.ocspUrl = ocspUrl;
    }

    public OCSPIllegalStateException(String message, String ocspUrl, Exception exception) {
        super(message, exception);
        this.ocspUrl = ocspUrl;
    }
}
