package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.Ocsp;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.OCSPCertificateStatusException;
import ee.ria.taraauthserver.error.exceptions.OCSPIllegalStateException;
import ee.ria.taraauthserver.error.exceptions.OCSPServiceNotAvailableException;
import ee.ria.taraauthserver.error.exceptions.OCSPValidationException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.IdCardAuthenticationResult;
import ee.ria.taraauthserver.utils.EstonianIdCodeUtil;
import ee.ria.taraauthserver.utils.X509Utils;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
import eu.webeid.security.validator.AuthTokenValidator;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.security.cert.X509Certificate;
import java.util.Map;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_NOT_YET_VALID;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_OCSP_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.INTERNAL_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Map.of;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@RestController
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
public class IdCardLoginController {
    public static final String CN_SERIALNUMBER = "SERIALNUMBER";
    public static final String CN_GIVEN_NAME = "GIVENNAME";
    public static final String CN_SURNAME = "SURNAME";


    private final IdCardAuthConfigurationProperties configurationProperties;
    private final OCSPValidator ocspValidator;
    private final AuthTokenValidator authTokenValidator;
    private final ChallengeNonceStore nonceStore;
    private final StatisticsLogger statisticsLogger;

    @PostMapping(path = "/auth/id/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> handleRequest(@RequestBody WebEidData data, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        logWebEidData(data);
        X509Certificate certificate;
        String nonce;
        try {
            nonce = nonceStore.getAndRemove().getBase64EncodedNonce();
        } catch (AuthTokenException e) {
            throw new BadRequestException(INVALID_REQUEST, e.getMessage(), e);
        }
        try {
            certificate = authTokenValidator.validate(data.getAuthToken(), nonce);
        } catch (CertificateExpiredException e) {
            throw new BadRequestException(IDC_CERT_EXPIRED, e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new BadRequestException(IDC_CERT_NOT_YET_VALID, e.getMessage(), e);
        } catch (AuthTokenException e) {
            throw new BadRequestException(INVALID_REQUEST, e.getMessage(), e);
        }
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);

        // TARA is using customized OCSP validation instead of AuthTokenValidator's built-in check
        if (configurationProperties.isOcspEnabled()) {
            IdCardAuthenticationResult authenticationResult = (IdCardAuthenticationResult) taraSession.getAuthenticationResult();
            try {
                Ocsp validatingOcspConf = ocspValidator.checkCert(certificate);
                updateAuthenticationResult(taraSession, certificate, validatingOcspConf.getUrl());
                statisticsLogger.logExternalTransaction(taraSession);
            } catch (OCSPServiceNotAvailableException e) {
                handleStatisticsLogging(taraSession, certificate, IDC_OCSP_NOT_AVAILABLE, e.getOcspUrl(), e);
                throw new ServiceNotAvailableException(IDC_OCSP_NOT_AVAILABLE, e.getMessage(), e);
            } catch (OCSPCertificateStatusException e) {
                handleStatisticsLogging(taraSession, certificate, e.getErrorCode(), e.getOcspUrl(), null);
                throw e;
            } catch (OCSPValidationException e) {
                handleStatisticsLogging(taraSession, certificate, e.getErrorCode(), e.getOcspUrl(), e);
                throw e;
            } catch (OCSPIllegalStateException e) {
                handleStatisticsLogging(taraSession, certificate, INTERNAL_ERROR, e.getOcspUrl(), e);
                throw e;
            } catch (Exception e) {
                handleStatisticsLogging(taraSession, certificate, INTERNAL_ERROR, null, e);
                throw e;
            }
        } else {
            log.info("Skipping OCSP validation because OCSP is disabled.");
            updateAuthenticationResult(taraSession, certificate, null);
        }

        return ResponseEntity.ok(of("status", "COMPLETED"));
    }

    private void handleStatisticsLogging(TaraSession taraSession, X509Certificate certificate, ErrorCode errorCode, String ocspUrl, Exception e) {
        IdCardAuthenticationResult authenticationResult = (IdCardAuthenticationResult) taraSession.getAuthenticationResult();
        updateAuthenticationResult(taraSession, certificate, ocspUrl);
        authenticationResult.setOcspUrl(ocspUrl);
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
        authenticationResult.setOcspUrl(validatingOcspConfUrl);
        authenticationResult.setFirstName(params.get(CN_GIVEN_NAME));
        authenticationResult.setLastName(params.get(CN_SURNAME));
        authenticationResult.setIdCode(idCode);
        authenticationResult.setCountry("EE");
        authenticationResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(idCode));
        authenticationResult.setAcr(configurationProperties.getLevelOfAssurance());
        authenticationResult.setSubject(authenticationResult.getCountry() + authenticationResult.getIdCode());
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
    }

    @Data
    static class WebEidData {
        private WebEidAuthToken authToken;
        private String extensionVersion;
        private String nativeAppVersion;
        private String statusDurationMs;
    }
}
