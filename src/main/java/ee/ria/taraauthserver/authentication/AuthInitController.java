package ee.ria.taraauthserver.authentication;


import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;
import static org.springframework.util.CollectionUtils.isEmpty;

@Slf4j
@Validated
@Controller
public class AuthInitController {
    public static final String AUTH_INIT_REQUEST_MAPPING = "/auth/init";
    private static final Predicate<String> SUPPORTED_LANGUAGES = java.util.regex.Pattern.compile("(?i)(et|en|ru)").asMatchPredicate();

    @Autowired
    private AuthConfigurationProperties taraProperties;

    @Autowired(required = false)
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

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
            model.addAttribute("country", getAllowedEidasCountryCode(loginRequestInfo.getRequestedScopes()));
            return "redirectToEidasInit";
        } else {
            return "loginView";
        }
    }

    private String getUiLanguage(String language, TaraSession taraSession) {
        return isNotEmpty(language) ? language : getDefaultOrRequestedLocale(taraSession);
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
        log.info(append("url.full", url), "OIDC login request for challenge: {}", value("tara.session.login_request_info.challenge", loginChallenge));
        try {
            ResponseEntity<TaraSession.LoginRequestInfo> response = hydraService.exchange(url, HttpMethod.GET, null, TaraSession.LoginRequestInfo.class);
            log.info(append("tara.session.login_request_info", response.getBody()), "OIDC login response for challenge: {}, Status code: {}",
                    loginChallenge,
                    response.getStatusCodeValue());
            validateResponse(response.getBody(), loginChallenge);
            return response.getBody();
        } catch (HttpClientErrorException.NotFound e) {
            log.error("Unable to fetch login request info!", e);
            throw new BadRequestException(ErrorCode.INVALID_LOGIN_CHALLENGE, "Login challenge not found.");
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
        List<String> requestedScopes = loginRequestInfo.getRequestedScopes();
        return requestedScopes.contains("eidasonly") && getAllowedEidasCountryCode(requestedScopes) != null;
    }

    private String getAllowedEidasCountryCode(List<String> requestedScopes) {
        if (eidasConfigurationProperties == null)
            throw new IllegalStateException("Cannot use eidasonly scope when eidas authentication is not loaded. Is not enabled in configuration?");

        String regex = "eidas:country:[a-z]{2}$";
        return requestedScopes.stream()
                .filter(rs -> rs.matches(regex))
                .map(this::getCountryCodeFromScope)
                .filter(rs -> eidasConfigurationProperties.getAvailableCountries().contains(rs))
                .findFirst()
                .orElse(null);
    }

    private String getCountryCodeFromScope(String eidasCountryScope) {
        return eidasCountryScope.replace("eidas:country:", "").toUpperCase();
    }
}
