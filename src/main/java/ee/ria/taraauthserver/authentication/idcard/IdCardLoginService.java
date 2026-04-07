package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.EstonianIdCodeUtil;
import ee.ria.taraauthserver.utils.X509Utils;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import eu.webeid.ocsp.exceptions.OCSPClientException;
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.resilientocsp.ResilientOcspCertificateRevocationChecker;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateRevokedException;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.ValidationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_FORBIDDEN;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_NOT_YET_VALID;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_OCSP_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_GOOD;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
public class IdCardLoginService {

    public static final String CN_SERIALNUMBER = "SERIALNUMBER";
    public static final String CN_GIVEN_NAME = "GIVENNAME";
    public static final String CN_SURNAME = "SURNAME";

    private final ClientRequestLogger requestLogger = new ClientRequestLogger(ClientRequestLogger.Service.OCSP, this.getClass());

    private final AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;
    private final AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy;
    private final AuthTokenValidator authTokenValidator;
    private final ChallengeNonceStore nonceStore;
    private final StatisticsLogger statisticsLogger;

    public void attemptLogin(IdCardLoginController.WebEidData data, TaraSession taraSession) {
        String nonce;
        try {
            nonce = nonceStore.getAndRemove().getBase64EncodedNonce();
        } catch (AuthTokenException e) {
            throw new BadRequestException(INVALID_REQUEST, e.getMessage(), e);
        }

        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);
        ValidationInfo validationInfo = handleTokenValidation(data.getAuthToken(), nonce, taraSession);
        logValidationInfo(validationInfo, taraSession);

        boolean isOcspEnabled = configurationProperties.getOcsp().isEnabled();
        if (!isOcspEnabled) {
            log.info("Skipping OCSP validation because OCSP is disabled.");
        }

        String eidasClientId = filterForEidasProxy.getClientId();
        X509Certificate certificate = validationInfo.subjectCertificate();
        if (taraSession.getOriginalClient().getClientId().equals(eidasClientId)) {
            validateIdCardValidForEidasAuthentication(certificate);
        }
        if (!isOcspEnabled) {
            updateAuthenticationResult(taraSession, certificate, null);
        }
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
    }

    private ValidationInfo handleTokenValidation(WebEidAuthToken authToken, String nonce, TaraSession taraSession) {
        try {
            return authTokenValidator.validate(authToken, nonce);
        } catch (CertificateExpiredException e) {
            throw new BadRequestException(IDC_CERT_EXPIRED, e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new BadRequestException(IDC_CERT_NOT_YET_VALID, e.getMessage(), e);
        } catch (ResilientUserCertificateRevokedException e) {
            logValidationInfo(e.getValidationInfo(), taraSession);
            throw new BadRequestException(IDC_REVOKED, e.getMessage(), e);
        } catch (ResilientUserCertificateOCSPCheckFailedException e) {
            logValidationInfo(e.getValidationInfo(), taraSession);
            throw new BadRequestException(handleResilientUserCertificateOCSPCheckFailedException(e), e.getMessage(), e);
        } catch (AuthTokenException e) {
            throw new BadRequestException(IDC_VALIDATION_ERROR_RESULT_OTHER, e.getMessage(), e);
        }
    }

    private static ErrorCode handleResilientUserCertificateOCSPCheckFailedException(ResilientUserCertificateOCSPCheckFailedException e) {
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

    private void validateIdCardValidForEidasAuthentication(X509Certificate certificate) {
        String issuerCn = X509Utils.getIssuerCNFromCertificate(certificate);
        List<String> forbiddenIssuerCns = filterForEidasProxy.getForbiddenIssuerCns();

        if (forbiddenIssuerCns.contains(issuerCn)) {
            throw new BadRequestException(IDC_CERT_FORBIDDEN, "eIDAS authentication with given certificate issuer CN has been forbidden in the application configuration");
        }
    }

    private void handleStatisticsLogging(TaraSession taraSession, X509Certificate certificate, ErrorCode errorCode,
                                         String ocspUrl, Exception e, OcspInfo ocspInfo) {
        TaraSession.IdCardAuthenticationResult authenticationResult = (TaraSession.IdCardAuthenticationResult) taraSession.getAuthenticationResult();
        updateAuthenticationResult(taraSession, certificate, ocspUrl);
        authenticationResult.setErrorCode(errorCode);
        if (e == null) {
            statisticsLogger.logExternalTransaction(taraSession, ocspInfo);
        } else {
            statisticsLogger.logExternalTransaction(taraSession, e, ocspInfo);
        }
    }

    private void updateAuthenticationResult(TaraSession taraSession, X509Certificate certificate, String validatingOcspConfUrl) {
        Map<String, String> params = X509Utils.getCertificateParams(certificate);
        String idCode = EstonianIdCodeUtil.getEstonianIdCode(params.get(CN_SERIALNUMBER));
        TaraSession.IdCardAuthenticationResult authenticationResult = (TaraSession.IdCardAuthenticationResult) taraSession.getAuthenticationResult();

        if (taraSession.isEmailScopeRequested()) {
            String email = X509Utils.getRfc822NameSubjectAltName(certificate);
            authenticationResult.setEmail(email);
        }
        authenticationResult.setErrorCode(null);
        authenticationResult.setOcspUrl(validatingOcspConfUrl);
        authenticationResult.setFirstName(params.get(CN_GIVEN_NAME));
        authenticationResult.setLastName(params.get(CN_SURNAME));
        authenticationResult.setIdCode(idCode);
        authenticationResult.setCountry("EE");
        authenticationResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(idCode));
        authenticationResult.setAcr(configurationProperties.getLevelOfAssurance());
        authenticationResult.setSubject(authenticationResult.getCountry() + authenticationResult.getIdCode());
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);
    }

    private void logValidationInfo(ValidationInfo validationInfo, TaraSession taraSession) {
        X509Certificate certificate = validationInfo.subjectCertificate();
        log.info("OCSP certificate info: Serialnumber=<{}>, SubjectDN=<{}>, issuerDN=<{}>",
                value("x509.serial_number", certificate.getSerialNumber().toString(16)),
                value("x509.subject.distinguished_name", certificate.getSubjectX500Principal().getName()),
                value("x509.issuer.distinguished_name", certificate.getIssuerX500Principal().getName()));

        int requestCount = 0;
        Iterator<RevocationInfo> iterator = validationInfo.revocationInfoList().iterator();
        while(iterator.hasNext()) {
            requestCount++;
            RevocationInfo revocationInfo = iterator.next();
            if (revocationInfo == null) {
                throw new IllegalArgumentException("Revocation info cannot be null");
            }
            Map<String, Object> ocspResponseAttributes = revocationInfo.ocspResponseAttributes();
            String ocspUrl = revocationInfo.ocspResponderUri().toString();
            OCSPReq ocspReq = (OCSPReq) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_REQUEST);
            OCSPResp ocspResp = null;
            try {
                ocspResp = (OCSPResp) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_RESPONSE);
            } catch (ClassCastException e) {
                log.atWarn()
                        .setCause(e)
                        .log("Failed to parse OCSP response");
            }
            Exception exception = (Exception) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_ERROR);
            Duration requestDuration = (Duration) ocspResponseAttributes.get(RevocationInfo.KEY_REQUEST_DURATION);
            boolean isLastRequest = !iterator.hasNext();
            ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics circuitBreakerStatistics
                    = (ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics) ocspResponseAttributes.get(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);
            Instant responseTime = (Instant) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_RESPONSE_TIME);
            OcspInfo ocspInfo = new OcspInfo(ocspResp, requestCount, requestDuration, isLastRequest, circuitBreakerStatistics, responseTime);
            if (exception == null) {
                if (!isLastRequest) {
                    throw new IllegalStateException("Only the last response can be successful");
                }
                updateAuthenticationResult(taraSession, certificate, ocspUrl);
                statisticsLogger.logExternalTransaction(taraSession, ocspInfo);
                logOcspSuccess(ocspUrl, ocspReq, ocspResp);
            } else {
                ErrorCode errorCode = getErrorCode(exception);
                handleStatisticsLogging(taraSession, certificate, errorCode, ocspUrl, exception, ocspInfo);
                logOcspFailure(ocspReq, ocspUrl, exception, ocspResp);
            }
        }
    }

    private static ErrorCode getErrorCode(Exception e) {
        if (e instanceof UserCertificateRevokedException) {
            return IDC_REVOKED;
        }
        if (e instanceof OCSPClientException exception) {
            return handleOSCPClientException(exception);
        }
        return IDC_VALIDATION_ERROR_RESULT_OTHER;
    }

    private static ErrorCode handleOSCPClientException(OCSPClientException e) {
        if (e.getResponseBody() == null) {
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

    private void logOcspFailure(OCSPReq ocspReq, String ocspUrl, Exception exception, OCSPResp ocspResp) {
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

    private void logOcspSuccess(String ocspUrl, OCSPReq ocspReq, OCSPResp ocspResp) {
        try {
            requestLogger.logRequest(ocspUrl, HttpMethod.POST, Base64.getEncoder().encodeToString(ocspReq.getEncoded()));
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

    public record OcspInfo(
            OCSPResp ocspResp,
            Integer requestCount,
            Duration requestDuration,
            boolean isLastRequest,
            ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics circuitBreakerStatistics,
            Instant responseTime
    ) {
    }
}
