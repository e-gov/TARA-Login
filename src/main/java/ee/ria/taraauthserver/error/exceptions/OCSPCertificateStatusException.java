package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.authentication.idcard.CertificateStatus;
import ee.ria.taraauthserver.error.ErrorCode;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;

@Getter
public class OCSPCertificateStatusException extends BadRequestException {
    private static final Map<CertificateStatus, ErrorCode> errorMap;

    static {
        errorMap = new HashMap<>();
        errorMap.put(CertificateStatus.REVOKED, ErrorCode.IDC_REVOKED);
        errorMap.put(CertificateStatus.UNKNOWN, ErrorCode.IDC_UNKNOWN);
    }

    private final String ocspUrl;

    public OCSPCertificateStatusException(CertificateStatus status, String ocspUrl) {
        super(errorMap.get(status), format("Invalid certificate status <%s> received", status));
        this.ocspUrl = ocspUrl;
    }
}
