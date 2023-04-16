package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.authentication.idcard.CertificateStatus;
import ee.ria.taraauthserver.error.ErrorCode;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
public class OCSPValidationException extends TaraException {
    private static final Map<CertificateStatus, ErrorCode> errorMap;

    static {
        errorMap = new HashMap<>();
        errorMap.put(CertificateStatus.GOOD, ErrorCode.IDC_VALIDATION_ERROR_RESULT_GOOD);
        errorMap.put(CertificateStatus.REVOKED, ErrorCode.IDC_VALIDATION_ERROR_RESULT_REVOKED);
        errorMap.put(CertificateStatus.UNKNOWN, ErrorCode.IDC_VALIDATION_ERROR_RESULT_UNKNOWN);
    }

    private final String ocspUrl;

    public OCSPValidationException(String message, CertificateStatus status, String ocspUrl) {
        this(message, status, ocspUrl, null);
    }

    public OCSPValidationException(String message, CertificateStatus status, String ocspUrl, Exception cause) {
        super(errorMap.get(status), message, cause);
        this.ocspUrl = ocspUrl;
    }
}
