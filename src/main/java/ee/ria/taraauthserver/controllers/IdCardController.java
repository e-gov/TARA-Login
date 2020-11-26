package ee.ria.taraauthserver.controllers;

import com.google.common.base.Splitter;
import ee.ria.taraauthserver.config.properties.Constants;
import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.error.OCSPServiceNotAvailableException;
import ee.ria.taraauthserver.error.OCSPValidationException;
import ee.ria.taraauthserver.error.UserAuthenticationFailedException;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.EstonianIdCodeUtil;
import ee.ria.taraauthserver.utils.OCSPValidator;
import ee.ria.taraauthserver.utils.X509Utils;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static ee.ria.taraauthserver.config.properties.Constants.HEADER_SSL_CLIENT_CERT;
import static ee.ria.taraauthserver.config.properties.Constants.TARA_SESSION;
import static ee.ria.taraauthserver.error.ErrorMessages.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled", matchIfMissing = true)
public class IdCardController {

    @Autowired
    private IdCardAuthConfigurationProperties configurationProperties;

    @Autowired
    OCSPValidator ocspValidator;

    @Autowired
    private SessionRepository sessionRepository;

    public static final String CN_SERIALNUMBER = "SERIALNUMBER";
    public static final String CN_GIVEN_NAME = "GIVENNAME";
    public static final String CN_SURNAME = "SURNAME";

    @GetMapping(path = {"/auth/id"})
    @ResponseBody
    public HashMap<String, String> handleRequest(HttpServletRequest request, HttpSession httpSession) {

        Session session = sessionRepository.findById(httpSession.getId());
        if (session == null)
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        TaraSession taraSession = session.getAttribute(Constants.TARA_SESSION);

        String encodedCertificate = request.getHeader(HEADER_SSL_CLIENT_CERT);
        if (encodedCertificate == null)
            throw new BadRequestException("Expected header '" + HEADER_SSL_CLIENT_CERT + "' could not be found in request");
        if (!StringUtils.hasLength(encodedCertificate))
            throw new BadRequestException("Unable to find certificate from request");
        if (taraSession == null)
            throw new BadRequestException("message.error.esteid.invalid-request");
        if (!taraSession.getState().equals(INIT_AUTH_PROCESS))
            throw new BadRequestException("message.error.esteid.invalid-request");

        X509Certificate certificate = X509Utils.toX509Certificate(encodedCertificate);
        validateUserCert(certificate);

        updateSessionStatus(session, taraSession);


        try {
            ocspValidator.checkCert(certificate);
        } catch (OCSPServiceNotAvailableException exception) {
            return createResponse("OCSP service is currently not available, please try again later", "message.idc.error.ocsp.not.available");
        } catch (OCSPValidationException exception) {
            return createResponse(exception.getMessage(), String.format("message.idc.%s", exception.getStatus().name().toLowerCase()));
        }

        addAuthResultToSession(session, taraSession, certificate);

        HashMap<String, String> map = new HashMap<>();
        map.put("status", "COMPLETED");
        return map;
    }

    @NotNull
    private HashMap<String, String> createResponse(String logMessage, String errorMessage) {
        HashMap<String, String> map = new HashMap<>();
        log.warn("OCSP validation failed: " + logMessage);
        map.put("status", "ERROR");
        map.put("errorMessage", errorMessage);
        return map;
    }

    private void updateSessionStatus(Session session, TaraSession taraSession) {
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private void addAuthResultToSession(Session session, TaraSession taraSession, X509Certificate certificate) {
        Map<String, String> params = Splitter.on(", ").withKeyValueSeparator("=").split(
                certificate.getSubjectDN().getName()
        );
        String idCode = EstonianIdCodeUtil.getEstonianIdCode(params.get(CN_SERIALNUMBER));

        TaraSession.AuthenticationResult authenticationResult = new TaraSession.AuthenticationResult();
        authenticationResult.setFirstName(params.get(CN_GIVEN_NAME));
        authenticationResult.setLastName(params.get(CN_SURNAME));
        authenticationResult.setIdCode(idCode);
        authenticationResult.setCountry("EE");
        authenticationResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(idCode));

        taraSession.setAuthenticationResult(authenticationResult);
        log.info("updated session in idcard controller is: " + taraSession);
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private void validateUserCert(X509Certificate x509Certificate) {
        try {
            x509Certificate.checkValidity();
        } catch (CertificateNotYetValidException e) {
            throw new UserAuthenticationFailedException(
                    "message.idc.certnotyetvalid",
                    "User certificate is not yet valid", e);
        } catch (CertificateExpiredException e) {
            throw new UserAuthenticationFailedException(
                    "message.idc.certexpired",
                    "User certificate is expired", e);
        }
    }

}
