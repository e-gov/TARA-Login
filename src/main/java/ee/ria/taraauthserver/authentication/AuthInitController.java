package ee.ria.taraauthserver.authentication;


import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.security.SessionManagementFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.validation.ConstraintViolation;
import javax.validation.Validator;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.marker.Markers.append;
import static org.springframework.util.CollectionUtils.isEmpty;

@Slf4j
@Validated
@Controller
public class AuthInitController {
    public static final String AUTH_INIT_REQUEST_MAPPING = "/auth/init";
    private static final Predicate<String> SUPPORTED_LANGUAGES = java.util.regex.Pattern.compile("(?i)(et|en|ru)").asMatchPredicate();
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());
    private final ClientRequestLogger govssoRequestLogger = new ClientRequestLogger(Service.GOVSSO_HYDRA, this.getClass());

    @Autowired
    private AuthConfigurationProperties taraProperties;

    @Autowired
    private AuthConfigurationProperties.GovssoHydraConfigurationProperties govssoHydraConfigurationProperties;

    @Autowired(required = false)
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private RestTemplate hydraRestTemplate;

    @Autowired
    private Validator validator;

    @GetMapping(value = AUTH_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public String authInit(
            @RequestParam(name = "login_challenge") @Size(max = 50)
            @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed") String loginChallenge,
            @RequestParam(name = "lang", required = false)
            @Pattern(regexp = "(et|en|ru)", message = "supported values are: 'et', 'en', 'ru'") String language,
            @SessionAttribute(value = TARA_SESSION) TaraSession newTaraSession, Model model) {
        log.info(append("http.request.locale", RequestUtils.getLocale()), "New authentication session");

        TaraSession.LoginRequestInfo loginRequestInfo = fetchLoginRequestInfo(loginChallenge);
        newTaraSession.setState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        newTaraSession.setLoginRequestInfo(loginRequestInfo);

        if (StringUtils.isNotBlank(govssoHydraConfigurationProperties.getClientId()) && govssoHydraConfigurationProperties.getClientId().equals(loginRequestInfo.getClientId())) {
            String govssoLoginChallenge = loginRequestInfo.getGovssoChallenge();
            if (govssoLoginChallenge != null && govssoLoginChallenge.matches("^[a-f0-9]{32}$")) {
                SessionManagementFilter.setGovssoFlowTraceId(govssoLoginChallenge);
                TaraSession.LoginRequestInfo govssoLoginRequestInfo = fetchGovssoLoginRequestInfo(govssoLoginChallenge);
                newTaraSession.setGovssoLoginRequestInfo(govssoLoginRequestInfo);
            } else {
                throw new BadRequestException(ErrorCode.INVALID_GOVSSO_LOGIN_CHALLENGE, "Incorrect GovSSO login challenge format.");
            }
        }

        if (loginRequestInfo.getRequestedScopes().isEmpty())
            throw new BadRequestException(ErrorCode.MISSING_SCOPE, "No scope is requested");

        List<AuthenticationType> allowedAuthenticationMethodsList = loginRequestInfo.getAllowedAuthenticationMethodsList(taraProperties);
        if (isEmpty(allowedAuthenticationMethodsList))
            throw new BadRequestException(ErrorCode.NO_VALID_AUTHMETHODS_AVAILABLE,
                    "No authentication methods match the requested level of assurance. Please check your authorization request");

        newTaraSession.setAllowedAuthMethods(allowedAuthenticationMethodsList);

        if (language == null)
            RequestUtils.setLocale(getDefaultOrRequestedLocale(newTaraSession));
        if (eidasOnlyWithCountryRequested(loginRequestInfo)) {
            model.addAttribute("country", getAllowedEidasCountryCode(loginRequestInfo));
            return "redirectToEidasInit";
        } else {
            return "loginView";
        }
    }

    private String getDefaultOrRequestedLocale(TaraSession taraSession) {
        return taraSession.getLoginRequestInfo().getOidcContext().getUiLocales()
                .stream()
                .filter(SUPPORTED_LANGUAGES)
                .findFirst()
                .orElse(taraProperties.getDefaultLocale());
    }

    private TaraSession.LoginRequestInfo fetchLoginRequestInfo(String loginChallenge) {
        String url = taraProperties.getHydraService().getLoginUrl() + "?login_challenge=" + loginChallenge;
        try {

            requestLogger.logRequest(url, HttpMethod.GET);
            var response = hydraRestTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    TaraSession.LoginRequestInfo.class);
            requestLogger.logResponse(response);

            validateResponse(response.getBody(), loginChallenge);
            return response.getBody();
        } catch (HttpClientErrorException.NotFound | HttpClientErrorException.Gone e) {
            log.error("Unable to fetch login request info!", e);
            throw new BadRequestException(ErrorCode.INVALID_LOGIN_CHALLENGE, "Login challenge not found.");
        }
    }

    private TaraSession.LoginRequestInfo fetchGovssoLoginRequestInfo(String ssoChallenge) {
        String requestUrl = govssoHydraConfigurationProperties.getLoginUrl() + "?login_challenge=" + ssoChallenge;
        try {
            govssoRequestLogger.logRequest(requestUrl, HttpMethod.GET);
            var response = hydraRestTemplate.exchange(
                    requestUrl,
                    HttpMethod.GET,
                    null,
                    TaraSession.LoginRequestInfo.class);
            govssoRequestLogger.logResponse(response);

            if (!response.getBody().getChallenge().equals(ssoChallenge))
                throw new IllegalStateException("Invalid GovSSO Hydra response: requested login_challenge does not match retrieved login_challenge");

            return response.getBody();
        } catch (HttpClientErrorException.NotFound | HttpClientErrorException.Gone e) {
            log.error("Unable to fetch SSO login request info!", e);
            throw new BadRequestException(ErrorCode.INVALID_GOVSSO_LOGIN_CHALLENGE, "Login challenge not found.");
        }
    }

    private void validateResponse(TaraSession.LoginRequestInfo response, String loginChallenge) {
        Set<ConstraintViolation<TaraSession.LoginRequestInfo>> constraintViolations = validator.validate(response);
        if (!constraintViolations.isEmpty() || !response.getChallenge().equals(loginChallenge))
            throw new IllegalStateException("Invalid hydra response: " + getConstraintViolationsAsString(constraintViolations));
    }

    private static String getConstraintViolationsAsString(Set<? extends ConstraintViolation<?>> constraintViolations) {
        return constraintViolations.stream()
                .map(cv -> cv == null ? "null" : cv.getPropertyPath() + ": " + cv.getMessage())
                .sorted().collect(Collectors.joining(", "));
    }

    public boolean eidasOnlyWithCountryRequested(TaraSession.LoginRequestInfo loginRequestInfo) {
        return loginRequestInfo.getRequestedScopes().contains("eidasonly") && getAllowedEidasCountryCode(loginRequestInfo) != null;
    }

    private String getAllowedEidasCountryCode(TaraSession.LoginRequestInfo loginRequestInfo) {
        if (eidasConfigurationProperties == null)
            throw new IllegalStateException("Cannot use eidasonly scope when eidas authentication is not loaded. Is not enabled in configuration?");

        SPType spType = loginRequestInfo.getClient().getMetaData().getOidcClient().getInstitution().getSector();
        String regex = "eidas:country:[a-z]{2}$";
        return loginRequestInfo.getRequestedScopes().stream()
                .filter(rs -> rs.matches(regex))
                .map(this::getCountryCodeFromScope)
                .filter(rs -> eidasConfigurationProperties.getAvailableCountries().get(spType).contains(rs))
                .findFirst()
                .orElse(null);
    }

    private String getCountryCodeFromScope(String eidasCountryScope) {
        return eidasCountryScope.replace("eidas:country:", "").toUpperCase();
    }
}
