package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.Ocsp;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.OCSPServiceNotAvailableException;
import ee.ria.taraauthserver.error.exceptions.OCSPValidationException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.IdCardAuthenticationResult;
import ee.ria.taraauthserver.utils.EstonianIdCodeUtil;
import ee.ria.taraauthserver.utils.X509Utils;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Map;

import static ee.ria.taraauthserver.authentication.idcard.CertificateStatus.REVOKED;
import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static ee.ria.taraauthserver.error.ErrorCode.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Map.of;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.springframework.context.i18n.LocaleContextHolder.getLocale;
import static org.springframework.http.HttpStatus.BAD_GATEWAY;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Slf4j
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
public class IdCardController {
    public static final String HEADER_SSL_CLIENT_CERT = "XCLIENTCERTIFICATE";
    public static final String CN_SERIALNUMBER = "SERIALNUMBER";
    public static final String CN_GIVEN_NAME = "GIVENNAME";
    public static final String CN_SURNAME = "SURNAME";
    public static final String AUTH_ID_REQUEST_MAPPING = "/auth/id";

    @Autowired
    private MessageSource messageSource;

    @Autowired
    private IdCardAuthConfigurationProperties configurationProperties;

    @Autowired
    private OCSPValidator ocspValidator;

    @GetMapping(path = {AUTH_ID_REQUEST_MAPPING})
    public ResponseEntity<Map<String, String>> handleRequest(HttpServletRequest request, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        initIdCardAuthentication(taraSession);

        X509Certificate certificate = getCertificateFromRequest(taraSession, request);
        try {
            certificate.checkValidity();
        } catch (CertificateNotYetValidException ex) {
            return createErrorResponse(taraSession, IDC_CERT_NOT_YET_VALID, "User certificate is not yet valid", BAD_REQUEST);
        } catch (CertificateExpiredException ex) {
            return createErrorResponse(taraSession, IDC_CERT_EXPIRED, "User certificate is expired", BAD_REQUEST);
        }

        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        if (configurationProperties.isOcspEnabled()) {
            try {
                Ocsp validatingOcspConf = ocspValidator.checkCert(certificate);
                updateAuthenticationResult(taraSession, certificate, validatingOcspConf);
            } catch (OCSPServiceNotAvailableException ex) {
                return createErrorResponse(taraSession, IDC_OCSP_NOT_AVAILABLE, "OCSP service is currently not available", BAD_GATEWAY);
            } catch (OCSPValidationException ex) {
                ErrorCode errorCode = ex.getStatus() == REVOKED ? IDC_REVOKED : IDC_UNKNOWN;
                return createErrorResponse(taraSession, errorCode, ex.getMessage(), BAD_REQUEST);
            }
        } else {
            log.info("Skipping OCSP validation because OCSP is disabled.");
            updateAuthenticationResult(taraSession, certificate, null);
        }

        return ResponseEntity.ok(of("status", "COMPLETED"));
    }

    private void initIdCardAuthentication(TaraSession taraSession) {
        IdCardAuthenticationResult authenticationResult = new IdCardAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.ID_CARD);
        taraSession.setAuthenticationResult(authenticationResult);
    }

    @NotNull
    private ResponseEntity<Map<String, String>> createErrorResponse(TaraSession taraSession, ErrorCode errorCode, String logMessage, HttpStatus httpStatus) {
        log.warn(append("error.code", errorCode.name()), "OCSP validation failed: {}", value("error.message", logMessage));
        taraSession.setState(AUTHENTICATION_FAILED);
        taraSession.getAuthenticationResult().setErrorCode(errorCode);
        String errorMessage = messageSource.getMessage(errorCode.getMessage(), null, getLocale());
        return ResponseEntity.status(httpStatus).body(of("status", "ERROR", "errorMessage", errorMessage));
    }

    private X509Certificate getCertificateFromRequest(TaraSession taraSession, HttpServletRequest request) {
        String encodedCertificate = request.getHeader(HEADER_SSL_CLIENT_CERT);
        if (encodedCertificate == null) {
            taraSession.getAuthenticationResult().setErrorCode(ESTEID_INVALID_REQUEST);
            throw new BadRequestException(ESTEID_INVALID_REQUEST, HEADER_SSL_CLIENT_CERT + " can not be null");
        }
        if (!StringUtils.hasLength(encodedCertificate)) {
            taraSession.getAuthenticationResult().setErrorCode(ESTEID_INVALID_REQUEST);
            throw new BadRequestException(ESTEID_INVALID_REQUEST, HEADER_SSL_CLIENT_CERT + " can not be an empty string");
        }
        return X509Utils.toX509Certificate(encodedCertificate);
    }

    private void updateAuthenticationResult(TaraSession taraSession, X509Certificate certificate, Ocsp validatingOcspConf) {
        Map<String, String> params = X509Utils.getCertificateParams(certificate);
        String idCode = EstonianIdCodeUtil.getEstonianIdCode(params.get(CN_SERIALNUMBER));
        IdCardAuthenticationResult authenticationResult = (IdCardAuthenticationResult) taraSession.getAuthenticationResult();

        if (validatingOcspConf != null) {
            authenticationResult.setOcspUrl(validatingOcspConf.getUrl());
        }

        if (taraSession.isEmailScopeRequested()) {
            String email = X509Utils.getRfc822NameSubjectAltName(certificate);
            authenticationResult.setEmail(email);
        }
        authenticationResult.setFirstName(params.get(CN_GIVEN_NAME));
        authenticationResult.setLastName(params.get(CN_SURNAME));
        authenticationResult.setIdCode(idCode);
        authenticationResult.setCountry("EE");
        authenticationResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(idCode));
        authenticationResult.setAcr(configurationProperties.getLevelOfAssurance());
        authenticationResult.setSubject(authenticationResult.getCountry() + authenticationResult.getIdCode());
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
    }
}
