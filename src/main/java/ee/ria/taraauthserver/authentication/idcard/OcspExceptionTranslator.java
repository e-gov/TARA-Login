package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.error.ErrorCode;
import eu.webeid.ocsp.exceptions.OCSPClientException;
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;

import java.io.IOException;
import java.util.List;

import static ee.ria.taraauthserver.error.ErrorCode.IDC_OCSP_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_GOOD;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_REVOKED;

@Slf4j
@UtilityClass
class OcspExceptionTranslator {

    public static ErrorCode translateOcspRequestError(Exception e) {
        if (e instanceof UserCertificateRevokedException) {
            return IDC_REVOKED;
        }
        if (e instanceof OCSPClientException exception) {
            return handleOSCPClientException(exception);
        }
        return IDC_VALIDATION_ERROR_RESULT_OTHER;
    }

    public static ErrorCode translateOcspCheckFailure(ResilientUserCertificateOCSPCheckFailedException e) {
        List<RevocationInfo> revocationInfoList = e.getValidationInfo().revocationInfoList();
        if (revocationInfoList.isEmpty()) {
            throw new IllegalArgumentException("Revocation info list cannot be empty");
        }
        RevocationInfo revocationInfo = revocationInfoList.get(revocationInfoList.size() - 1);
        if (revocationInfo == null) {
            throw new IllegalArgumentException("Revocation info cannot be null");
        }
        OCSPResp ocspResp;
        try {
            ocspResp = (OCSPResp) revocationInfo.ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_RESPONSE);
        } catch (ClassCastException exception) {
            return IDC_OCSP_NOT_AVAILABLE;
        }
        return getErrorCodeFromOcspResponse(ocspResp);
    }

    private static ErrorCode handleOSCPClientException(OCSPClientException e) {
        if (e.getResponseBody() == null || e.getResponseBody().length == 0) {
            return IDC_OCSP_NOT_AVAILABLE;
        }
        OCSPResp ocspResp;
        try {
            ocspResp = new OCSPResp(e.getResponseBody());
        } catch (IOException ioException) {
            log.atError()
                    .setCause(e)
                    .log("Failed to parse OCSP response");
            return IDC_VALIDATION_ERROR_RESULT_OTHER;
        }
        return getErrorCodeFromOcspResponse(ocspResp);
    }

    private static ErrorCode getErrorCodeFromOcspResponse(OCSPResp ocspResp) {
        if (ocspResp == null) {
            return IDC_OCSP_NOT_AVAILABLE;
        }
        CertificateStatus status;
        try {
            status = getCertificateStatus(ocspResp);
        } catch (OCSPException e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to decode OCSP response");
            return IDC_VALIDATION_ERROR_RESULT_OTHER;
        }
        if (status == null) {
            return IDC_VALIDATION_ERROR_RESULT_GOOD;
        }
        if (status instanceof RevokedStatus) {
            return IDC_VALIDATION_ERROR_RESULT_REVOKED;
        }
        return IDC_VALIDATION_ERROR_RESULT_OTHER;
    }

    private static CertificateStatus getCertificateStatus(OCSPResp ocspResp) throws OCSPException {
        BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        SingleResp certStatusResponse = basicResponse.getResponses()[0];
        return certStatusResponse.getCertStatus();
    }
}