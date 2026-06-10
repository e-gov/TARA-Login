package ee.ria.taraauthserver.authentication.idcard;

import eu.webeid.resilientocsp.ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

@Slf4j
record OcspResponseAttributes(
        String ocspUrl,
        OCSPReq ocspRequest,
        OCSPResp ocspResponse,
        Exception error,
        Duration requestDuration,
        CircuitBreakerStatistics circuitBreakerStatistics,
        Instant responseTime,
        int requestNumber,
        boolean lastRequest
) {

    static OcspResponseAttributes parse(RevocationInfo revocationInfo, int requestNumber, boolean lastRequest) {
        if (revocationInfo == null) {
            throw new IllegalArgumentException("Revocation info cannot be null");
        }
        Map<String, Object> ocspResponseAttributes = revocationInfo.ocspResponseAttributes();
        String ocspUrl = revocationInfo.ocspResponderUri().toString();
        OCSPReq ocspRequest = (OCSPReq) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_REQUEST);
        OCSPResp ocspResponse = null;
        try {
            ocspResponse = (OCSPResp) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_RESPONSE);
        } catch (ClassCastException e) {
            log.atWarn()
                    .setCause(e)
                    .log("Failed to parse OCSP response");
        }
        Exception error = (Exception) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_ERROR);
        Duration requestDuration = (Duration) ocspResponseAttributes.get(RevocationInfo.KEY_REQUEST_DURATION);
        CircuitBreakerStatistics circuitBreakerStatistics
                = (CircuitBreakerStatistics) ocspResponseAttributes.get(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);
        Instant responseTime = (Instant) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_RESPONSE_TIME);
        return new OcspResponseAttributes(ocspUrl, ocspRequest, ocspResponse, error, requestDuration,
                circuitBreakerStatistics, responseTime, requestNumber, lastRequest);
    }

    OcspInfo toOcspInfo() {
        return new OcspInfo(ocspResponse, requestNumber, requestDuration, lastRequest,
                circuitBreakerStatistics, responseTime);
    }
}
