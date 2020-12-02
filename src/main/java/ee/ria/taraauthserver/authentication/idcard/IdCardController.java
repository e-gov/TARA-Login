package ee.ria.taraauthserver.authentication.idcard;

import com.google.common.base.Splitter;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.OCSPServiceNotAvailableException;
import ee.ria.taraauthserver.error.exceptions.OCSPValidationException;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.EstonianIdCodeUtil;
import ee.ria.taraauthserver.utils.SessionUtils;
import ee.ria.taraauthserver.utils.X509Utils;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static ee.ria.taraauthserver.error.ErrorTranslationCodes.ESTEID_INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT;
import static ee.ria.taraauthserver.utils.SessionUtils.getAuthSessionInState;
import static ee.ria.taraauthserver.utils.SessionUtils.updateSession;
import static java.lang.String.format;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled", matchIfMissing = true)
public class IdCardController {

    @Autowired
    private MessageSource messageSource;

    @Autowired
    private IdCardAuthConfigurationProperties configurationProperties;

    @Autowired
    OCSPValidator ocspValidator;

    public static final String HEADER_SSL_CLIENT_CERT = "XCLIENTCERTIFICATE";
    public static final String CN_SERIALNUMBER = "SERIALNUMBER";
    public static final String CN_GIVEN_NAME = "GIVENNAME";
    public static final String CN_SURNAME = "SURNAME";

    @GetMapping(path = {"/auth/id"})
    @ResponseBody
    public ModelAndView handleRequest(HttpServletRequest request) {

        TaraSession taraSession = getAuthSessionInState(INIT_AUTH_PROCESS);

        String encodedCertificate = request.getHeader(HEADER_SSL_CLIENT_CERT);
        validateEncodedCertificate(encodedCertificate);

        X509Certificate certificate = X509Utils.toX509Certificate(encodedCertificate);

        try {
            certificate.checkValidity();
        } catch (CertificateNotYetValidException e) {
            return createErrorResponse("User certificate is not yet valid",
                    getLocalizedMessage("message.idc.certnotyetvalid"),
                    HttpStatus.BAD_REQUEST);
        } catch (CertificateExpiredException e) {
            return createErrorResponse("User certificate is expired",
                    getLocalizedMessage("message.idc.certexpired"),
                    HttpStatus.BAD_REQUEST);
        }

        updateSessionStatus(taraSession);

        try {
            ocspValidator.checkCert(certificate);
        } catch (OCSPServiceNotAvailableException exception) {
            return createErrorResponse("OCSP service is currently not available, please try again later",
                    getLocalizedMessage("message.idc.error.ocsp.not.available"), HttpStatus.BAD_GATEWAY);
        } catch (OCSPValidationException exception) {
            return createErrorResponse(exception.getMessage(),
                    getLocalizedMessage(format("message.idc.%s", exception.getStatus().name().toLowerCase())),
                    HttpStatus.BAD_REQUEST);
        }

        addAuthResultToSession(taraSession, certificate);

        return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "COMPLETED"));
    }

    private void validateEncodedCertificate(String encodedCertificate) {
        if (encodedCertificate == null)
            throw new BadRequestException(ESTEID_INVALID_REQUEST, HEADER_SSL_CLIENT_CERT + " can not be null");
        if (!StringUtils.hasLength(encodedCertificate))
            throw new BadRequestException(ESTEID_INVALID_REQUEST, HEADER_SSL_CLIENT_CERT + " can not be an empty string");
    }

    @NotNull
    private String getLocalizedMessage(String code) {
        return messageSource.getMessage(code, null,
                LocaleContextHolder.getLocale());
    }

    @NotNull
    private ModelAndView createErrorResponse(String logMessage, String errorMessage, HttpStatus httpStatus) {
        Map<String, String> map = new HashMap<>();
        log.warn("OCSP validation failed: " + logMessage);
        map.put("status", "ERROR");
        map.put("errorMessage", errorMessage);
        ModelAndView modelAndView = new ModelAndView(new MappingJackson2JsonView(), map);
        modelAndView.setStatus(httpStatus);
        return modelAndView;
    }

    private void updateSessionStatus(TaraSession taraSession) {
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        updateSession(taraSession);
    }

    private void addAuthResultToSession(TaraSession taraSession, X509Certificate certificate) {
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
        authenticationResult.setAcr(configurationProperties.getLevelOfAssurance());
        authenticationResult.setAmr(AuthenticationType.IDCard);
        authenticationResult.setSubject(authenticationResult.getCountry() + authenticationResult.getIdCode());
        taraSession.setState(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        taraSession.setAuthenticationResult(authenticationResult);
        log.info("updated session in idcard controller is: " + taraSession);
        updateSession(taraSession);
    }

}
