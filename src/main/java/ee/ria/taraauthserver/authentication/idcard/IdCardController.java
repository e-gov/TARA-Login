package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.OCSPServiceNotAvailableException;
import ee.ria.taraauthserver.error.exceptions.OCSPValidationException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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

        String encodedCertificate = request.getHeader(HEADER_SSL_CLIENT_CERT);
        validateEncodedCertificate(encodedCertificate);

        X509Certificate certificate = X509Utils.toX509Certificate(encodedCertificate);
        try {
            certificate.checkValidity();
        } catch (CertificateNotYetValidException ex) {
            taraSession.setState(AUTHENTICATION_FAILED);
            return createErrorResponse(IDC_CERT_NOT_YET_VALID, "User certificate is not yet valid", BAD_REQUEST);
        } catch (CertificateExpiredException ex) {
            taraSession.setState(AUTHENTICATION_FAILED);
            return createErrorResponse(IDC_CERT_EXPIRED, "User certificate is expired", BAD_REQUEST);
        }

        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        try {
            ocspValidator.checkCert(certificate);
        } catch (OCSPServiceNotAvailableException ex) {
            taraSession.setState(AUTHENTICATION_FAILED);
            return createErrorResponse(IDC_OCSP_NOT_AVAILABLE, "OCSP service is currently not available", BAD_GATEWAY);
        } catch (OCSPValidationException ex) {
            taraSession.setState(AUTHENTICATION_FAILED);
            CertificateStatus status = ex.getStatus();
            ErrorCode errorCode = status == REVOKED ? IDC_REVOKED : IDC_UNKNOWN;
            return createErrorResponse(errorCode, ex.getMessage(), BAD_REQUEST);
        }

        addAuthResultToSession(taraSession, certificate);
        return ResponseEntity.ok(of("status", "COMPLETED"));
    }

    @NotNull
    private ResponseEntity<Map<String, String>> createErrorResponse(ErrorCode errorCode, String logMessage, HttpStatus httpStatus) {
        log.warn(append("error.code", errorCode.name()), "OCSP validation failed: {}", value("error.message", logMessage));
        String errorMessage = messageSource.getMessage(errorCode.getMessage(), null, getLocale());
        return ResponseEntity.status(httpStatus).body(of("status", "ERROR", "errorMessage", errorMessage));
    }

    private void validateEncodedCertificate(String encodedCertificate) {
        if (encodedCertificate == null)
            throw new BadRequestException(ESTEID_INVALID_REQUEST, HEADER_SSL_CLIENT_CERT + " can not be null");
        if (!StringUtils.hasLength(encodedCertificate))
            throw new BadRequestException(ESTEID_INVALID_REQUEST, HEADER_SSL_CLIENT_CERT + " can not be an empty string");
    }

    private void addAuthResultToSession(TaraSession taraSession, X509Certificate certificate) {

        Map<String, String> params = getCertificateParams(certificate);
        String idCode = EstonianIdCodeUtil.getEstonianIdCode(params.get(CN_SERIALNUMBER));
        TaraSession.AuthenticationResult authenticationResult = new TaraSession.AuthenticationResult();

        if (emailIsRequested(taraSession)) {
            String email = X509Utils.getRfc822NameSubjectAltName(certificate);
            authenticationResult.setEmail(email);
        }
        authenticationResult.setFirstName(params.get(CN_GIVEN_NAME));
        authenticationResult.setLastName(params.get(CN_SURNAME));
        authenticationResult.setIdCode(idCode);
        authenticationResult.setCountry("EE");
        authenticationResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(idCode));
        authenticationResult.setAcr(configurationProperties.getLevelOfAssurance());
        authenticationResult.setAmr(AuthenticationType.ID_CARD);
        authenticationResult.setSubject(authenticationResult.getCountry() + authenticationResult.getIdCode());
        taraSession.setState(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        taraSession.setAuthenticationResult(authenticationResult);
    }

    private boolean emailIsRequested(TaraSession taraSession) {
        List<String> scopes = Optional.of(taraSession)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getRequestedScopes)
                .orElse(null);
        return scopes != null && scopes.contains(TaraScope.EMAIL.getFormalName());
    }

    @NotNull
    private Map<String, String> getCertificateParams(X509Certificate certificate) {
        String[] test1 = certificate.getSubjectDN().getName().split(", ");
        Map<String, String> params = new HashMap<>();
        for (String s : test1) {
            String[] t = s.split("=");
            params.put(t[0], t[1]);
        }
        return params;
    }
}
