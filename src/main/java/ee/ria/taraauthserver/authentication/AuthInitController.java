package ee.ria.taraauthserver.authentication;


import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.AuthFlowTimeoutException;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.NotFoundException;
import ee.ria.taraauthserver.govsso.GovssoService;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.security.SessionManagementFilter;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.update.InitAuthSessionUpdate;
import ee.ria.taraauthserver.utils.RequestUtils;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URISyntaxException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.DEFAULT_LOCALE;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.marker.Markers.append;
import static org.springframework.util.CollectionUtils.isEmpty;

@Slf4j
@Validated
@Controller
public class AuthInitController {
    public static final String AUTH_INIT_REQUEST_MAPPING = "/auth/init";
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());

    @Autowired
    private AuthConfigurationProperties taraProperties;

    @Autowired
    private AuthConfigurationProperties.GovSsoConfigurationProperties govSsoConfigurationProperties;

    @Autowired(required = false)
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private RestTemplate hydraRestTemplate;

    @Autowired
    private GovssoService govssoService;

    @Autowired
    private Validator validator;

    @GetMapping(value = AUTH_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public String authInit(
            @RequestParam(name = "login_challenge") @Size(max = 50)
            @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed") String loginChallenge,
            @RequestParam(name = "lang", required = false)
            @Pattern(regexp = "(et|en|ru)", message = "supported values are: 'et', 'en', 'ru'") String language,
            @SessionAttribute(value = TARA_SESSION) TaraSession newTaraSession,
            @CookieValue(value = "__Host-LOCALE", defaultValue = DEFAULT_LOCALE) String cookieLocale,
        Model model) {
        log.info(append("http.request.locale", RequestUtils.getLocale()), "New authentication session");
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, newTaraSession);

        TaraSession.LoginRequestInfo loginRequestInfo = fetchLoginRequestInfo(loginChallenge);

        TaraSession.LoginRequestInfo govSsoLoginRequestInfo = null;
        if (govssoService.isGovssoClient(loginRequestInfo.getClientId())) {
            String govSsoLoginChallenge = loginRequestInfo.getGovSsoChallenge();
            if (govSsoLoginChallenge == null || !govSsoLoginChallenge.matches("^[a-f0-9]{32}$")) {
                throw new BadRequestException(ErrorCode.INVALID_GOVSSO_LOGIN_CHALLENGE, "Incorrect GovSSO login challenge format.");
            }
            SessionManagementFilter.setGovSsoFlowTraceId(govSsoLoginChallenge);
            govSsoLoginRequestInfo = fetchGovSsoLoginRequestInfo(govSsoLoginChallenge);
        }

        List<AuthenticationType> allowedAuthMethods = loginRequestInfo.getAllowedAuthenticationMethodsList(taraProperties);
        newTaraSession.accept(new InitAuthSessionUpdate(
                loginRequestInfo,
                govSsoLoginRequestInfo,
                allowedAuthMethods
        ));

        Duration authFlowTimeout = null;
        if(loginRequestInfo.getRequestedAt() != null){
            OffsetDateTime timeoutDatetime = loginRequestInfo.getRequestedAt().plusSeconds(taraProperties.getAuthFlowTimeout().getSeconds());
            if (timeoutDatetime.isBefore(OffsetDateTime.now())) {
                throw new AuthFlowTimeoutException("User did not authenticate before the login session timeout");
            }
            authFlowTimeout = Duration.between(OffsetDateTime.now(), timeoutDatetime);
        }

        if (loginRequestInfo.getRequestedScopes().isEmpty()) {
            throw new BadRequestException(ErrorCode.MISSING_SCOPE, "No scope is requested");
        }

        if (isEmpty(allowedAuthMethods)) {
            throw new BadRequestException(ErrorCode.NO_VALID_AUTHMETHODS_AVAILABLE,
                    "No authentication methods match the requested level of assurance. Please check your authorization request");
        }

        if (language == null) {
            language = getDefaultOrRequestedLocale(newTaraSession, cookieLocale);
            RequestUtils.setLocale(language);
        }
        newTaraSession.setChosenLanguage(language);

        if (eidasOnlyWithCountryRequested(loginRequestInfo)) {
            model.addAttribute("country", getAllowedEidasCountryCode(loginRequestInfo));
            return "redirectToEidasInit";
        } else {
            addSelfServiceUrlToModel(model, govSsoConfigurationProperties.getSelfServiceUrl(), language);
            if (authFlowTimeout != null){
                model.addAttribute("secondsToAuthFlowTimeout", authFlowTimeout.getSeconds());
            }
            return "loginView";
        }
    }

    public void addSelfServiceUrlToModel(Model model, String selfServiceUrl, String language) {
        try {
            if(StringUtils.isNotBlank(selfServiceUrl)) {
                model.addAttribute("selfServiceUrl",
                        new URIBuilder(selfServiceUrl)
                                .addParameter("lang", language)
                                .build()
                                .toString());
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Failed to build self service URL: " + e.getMessage(), e);
        }
    }

    private String getDefaultOrRequestedLocale(TaraSession taraSession, String cookieLocale) {
        return taraSession.getLoginRequestInfo().getOidcContext().getUiLocales()
            .stream()
            .map(String::toLowerCase)
            .filter(RequestUtils.SUPPORTED_LANGUAGES)
            .findFirst()
            .or(() -> Optional.ofNullable(cookieLocale)
                .map(String::toLowerCase)
                .filter(RequestUtils.SUPPORTED_LANGUAGES))
            .orElse(DEFAULT_LOCALE);
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

    private TaraSession.LoginRequestInfo fetchGovSsoLoginRequestInfo(String ssoChallenge) {
        try {
            return govssoService.fetchGovSsoLoginRequestInfo(ssoChallenge);
        } catch (NotFoundException e) {
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
