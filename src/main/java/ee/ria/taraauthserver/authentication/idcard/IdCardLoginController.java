package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.IdCardAuthenticationResult;
import ee.ria.taraauthserver.utils.EstonianIdCodeUtil;
import ee.ria.taraauthserver.utils.X509Utils;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import eu.webeid.security.RevocationInfo;
import eu.webeid.security.TaraUserCertificateOCSPCheckFailedException;
import eu.webeid.security.TaraUserCertificateRevokedException;
import eu.webeid.security.ValidationInfo;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
import eu.webeid.security.exceptions.OcspClientException;
import eu.webeid.security.validator.AuthTokenValidator;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.FilterForEidasProxy;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_FORBIDDEN;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_NOT_YET_VALID;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_OCSP_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Map.of;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@RestController
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
public class IdCardLoginController {
    public static final String CN_SERIALNUMBER = "SERIALNUMBER";
    public static final String CN_GIVEN_NAME = "GIVENNAME";
    public static final String CN_SURNAME = "SURNAME";

    private final ClientRequestLogger requestLogger = new ClientRequestLogger(ClientRequestLogger.Service.OCSP, this.getClass());

    private final IdCardAuthConfigurationProperties configurationProperties;
    private final FilterForEidasProxy filterForEidasProxy;
    private final AuthTokenValidator authTokenValidator;
    private final ChallengeNonceStore nonceStore;
    private final StatisticsLogger statisticsLogger;

    @PostMapping(path = "/auth/id/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> handleRequest(@RequestBody WebEidData data, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        logWebEidData(data);
        String nonce;
        try {
            nonce = nonceStore.getAndRemove().getBase64EncodedNonce();
        } catch (AuthTokenException e) {
            throw new BadRequestException(INVALID_REQUEST, e.getMessage(), e);
        }

        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);

        ValidationInfo validationInfo;
        try {
            validationInfo = authTokenValidator.validate(data.getAuthToken(), nonce);
        } catch (CertificateExpiredException e) {
            throw new BadRequestException(IDC_CERT_EXPIRED, e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new BadRequestException(IDC_CERT_NOT_YET_VALID, e.getMessage(), e);
        } catch (TaraUserCertificateRevokedException e) {
            logValidationInfo(e.getValidationInfo(), taraSession);
            throw new BadRequestException(IDC_REVOKED, e.getMessage(), e);
        } catch (TaraUserCertificateOCSPCheckFailedException e) {
            logValidationInfo(e.getValidationInfo(), taraSession);
            throw new BadRequestException(INVALID_REQUEST, e.getMessage(), e);
        } catch (AuthTokenException e) {
            throw new BadRequestException(INVALID_REQUEST, e.getMessage(), e);
        }

        String eidasClientId =  filterForEidasProxy.getClientId();
        X509Certificate certificate = validationInfo.getSubjectCertificate();
        if(taraSession.getOriginalClient().getClientId().equals(eidasClientId)) {
            validateIdCardValidForEidasAuthentication(certificate);
        }

        logValidationInfo(validationInfo, taraSession);
        return ResponseEntity.ok(of("status", "COMPLETED"));
    }

    private static ErrorCode getErrorCodeByExceptionType(Exception e) {
        if (e instanceof TaraUserCertificateRevokedException) {
            return IDC_REVOKED;
        }
        if (e instanceof OcspClientException) {
            return IDC_OCSP_NOT_AVAILABLE;
        }
        return INVALID_REQUEST;
    }

    private void validateIdCardValidForEidasAuthentication(X509Certificate certificate) {
        String issuerCn = X509Utils.getIssuerCNFromCertificate(certificate);
        List<String> forbiddenIssuerCns = filterForEidasProxy.getForbiddenIssuerCns();

        if (forbiddenIssuerCns.contains(issuerCn)) {
            throw new BadRequestException(IDC_CERT_FORBIDDEN, "eIDAS authentication with given certificate issuer CN has been forbidden in the application configuration");
        }
    }

    private void handleStatisticsLogging(TaraSession taraSession, X509Certificate certificate, ErrorCode errorCode, String ocspUrl, Exception e) {
        IdCardAuthenticationResult authenticationResult = (IdCardAuthenticationResult) taraSession.getAuthenticationResult();
        updateAuthenticationResult(taraSession, certificate, ocspUrl);
        authenticationResult.setErrorCode(errorCode);
        if (e == null) {
            statisticsLogger.logExternalTransaction(taraSession);
        } else {
            statisticsLogger.logExternalTransaction(taraSession, e);
        }
    }

    private void logWebEidData(WebEidData data) {
        WebEidAuthToken authToken = data.authToken;
        LogstashMarker marker = append("tara.webeid.extension_version", data.extensionVersion)
                .and(append("tara.webeid.native_app_version", data.nativeAppVersion))
                .and(append("tara.webeid.status_duration_ms", data.statusDurationMs))
                .and(append("tara.webeid.code", "SUCCESS"))
                .and(append("tara.webeid.auth_token.unverified_certificate", authToken.getUnverifiedCertificate()))
                .and(append("tara.webeid.auth_token.signature", authToken.getSignature()))
                .and(append("tara.webeid.auth_token.algorithm", authToken.getAlgorithm()))
                .and(append("tara.webeid.auth_token.format", authToken.getFormat()));
        log.info(marker, "Client-side Web eID operation successful");
    }

    private void updateAuthenticationResult(TaraSession taraSession, X509Certificate certificate, String validatingOcspConfUrl) {
        Map<String, String> params = X509Utils.getCertificateParams(certificate);
        String idCode = EstonianIdCodeUtil.getEstonianIdCode(params.get(CN_SERIALNUMBER));
        IdCardAuthenticationResult authenticationResult = (IdCardAuthenticationResult) taraSession.getAuthenticationResult();

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
        X509Certificate certificate = validationInfo.getSubjectCertificate();
        log.info("OCSP certificate info: Serialnumber=<{}>, SubjectDN=<{}>, issuerDN=<{}>",
                value("x509.serial_number", certificate.getSerialNumber().toString()),
                value("x509.subject.distinguished_name", certificate.getSubjectX500Principal().getName()),
                value("x509.issuer.distinguished_name", certificate.getIssuerX500Principal().getName()));
        List<RevocationInfo> revocationInfoList = validationInfo.getRevocationInfoList();
        if (revocationInfoList.isEmpty()) {
            return;
        }
        // TODO Defaults
        int httpStatusCode = 400;

        // TODO Should these be inside the loop?
        RevocationInfo revocationInfo;
        Exception exception;
        String ocspUrl;
        Map<String, Object> ocspResponseAttributes;
        ErrorCode errorCode;
        OCSPReq ocspReq;
        OCSPResp ocspResp;
        byte[] encodedOcspResp;
        for (int i = 0; i < revocationInfoList.size(); i++) {
            revocationInfo = revocationInfoList.get(i);
            if (revocationInfo == null) {
                continue;
            }
            ocspResponseAttributes = revocationInfo.getOcspResponseAttributes();
            ocspUrl = revocationInfo.getOcspResponderUri().toString();
            ocspReq = (OCSPReq) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_REQUEST);
            ocspResp = (OCSPResp) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_RESPONSE);
            exception = (Exception) ocspResponseAttributes.get(RevocationInfo.KEY_OCSP_ERROR);
            if (i == revocationInfoList.size() - 1) {
                if (exception == null) {
                    updateAuthenticationResult(taraSession, certificate, ocspUrl);
                    taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
                    statisticsLogger.logExternalTransaction(taraSession);
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
                    return;
                }
            }
            errorCode = getErrorCodeByExceptionType(exception);
            handleStatisticsLogging(taraSession, certificate, errorCode, ocspUrl, exception);
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
                if (exception instanceof OcspClientException ocspClientException) {
                    encodedOcspResp = ocspClientException.getResponseBody();
                    httpStatusCode = ocspClientException.getStatusCode() != null
                            ? ocspClientException.getStatusCode()
                            // TODO What should be the default value?
                            : HttpStatus.BAD_REQUEST.value();
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
    }

    @Data
    static class WebEidData {
        private WebEidAuthToken authToken;
        private String extensionVersion;
        private String nativeAppVersion;
        private String statusDurationMs;
    }
}
