package ee.ria.taraauthserver.error.exceptions;

import lombok.Getter;

public class OCSPServiceNotAvailableException extends RuntimeException {
    @Getter
    private String ocspUrl;

    public OCSPServiceNotAvailableException(String message, String ocspUrl) {
        super(message);
        this.ocspUrl = ocspUrl;
    }

    public OCSPServiceNotAvailableException(String message, String ocspUrl, Exception e) {
        super(message, e);
        this.ocspUrl = ocspUrl;
    }
}
