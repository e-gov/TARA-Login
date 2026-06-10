package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.logging.ClientRequestLogger;
import eu.webeid.ocsp.exceptions.OCSPClientException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Base64;

@Slf4j
@Component
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
class OcspRequestResponseLogger {

    private final ClientRequestLogger requestLogger;

    public OcspRequestResponseLogger() {
        // IdCardLoginService.class preserves the OCSP wire-log logger name relied upon by log monitoring.
        this(new ClientRequestLogger(ClientRequestLogger.Service.OCSP, IdCardLoginService.class));
    }

    OcspRequestResponseLogger(ClientRequestLogger requestLogger) {
        this.requestLogger = requestLogger;
    }

    void logSuccess(String ocspUrl, OCSPReq ocspReq, OCSPResp ocspResp) {
        try {
            if (ocspReq != null) {
                requestLogger.logRequest(ocspUrl, HttpMethod.POST, Base64.getEncoder().encodeToString(ocspReq.getEncoded()));
            } else {
                requestLogger.logRequest(ocspUrl, HttpMethod.POST);
            }
        } catch (IOException e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to encode OCSP request");
        }
        try {
            requestLogger.logResponse(HttpStatus.OK.value(), Base64.getEncoder().encodeToString(ocspResp.getEncoded()));
        } catch (IOException e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to encode OCSP response");
        }
    }

    void logFailure(String ocspUrl, OCSPReq ocspReq, OCSPResp ocspResp, Exception exception) {
        try {
            if (ocspReq != null) {
                requestLogger.logRequest(ocspUrl, HttpMethod.POST, Base64.getEncoder().encodeToString(ocspReq.getEncoded()));
            } else {
                requestLogger.logRequest(ocspUrl, HttpMethod.POST);
            }
        } catch (IOException e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to encode OCSP request");
        }

        int httpStatusCode = -1;
        byte[] encodedOcspResp;
        try {
            if (exception instanceof OCSPClientException ocspClientException) {
                encodedOcspResp = ocspClientException.getResponseBody();
                httpStatusCode = ocspClientException.getStatusCode() != null
                        ? ocspClientException.getStatusCode()
                        : httpStatusCode;
            } else {
                encodedOcspResp = ocspResp.getEncoded();
                // A non-OCSPClientException failure (e.g. a definitive REVOKED/UNKNOWN status) means the OCSP HTTP
                // request itself succeeded, so the response was served with HTTP 200.
                httpStatusCode = HttpStatus.OK.value();
            }
            if (encodedOcspResp != null) {
                requestLogger.logResponse(httpStatusCode, Base64.getEncoder().encodeToString(encodedOcspResp));
            } else {
                requestLogger.logResponse(httpStatusCode);
            }
        } catch (IOException e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to encode OCSP response");
        }
    }
}
