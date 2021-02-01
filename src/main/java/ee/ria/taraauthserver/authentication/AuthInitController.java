package ee.ria.taraauthserver.authentication;


import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
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
import java.util.*;
import java.util.stream.Collectors;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;
import static org.springframework.util.CollectionUtils.isEmpty;

@Slf4j
@Validated
@Controller
public class AuthInitController {
    public static final String AUTH_INIT_REQUEST_MAPPING = "/auth/init";

    @Autowired
    private AuthConfigurationProperties taraProperties;

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
            @SessionAttribute(value = TARA_SESSION) TaraSession newTaraSession) {

        TaraSession.LoginRequestInfo loginRequestInfo = fetchLoginRequestInfo(loginChallenge);
        newTaraSession.setState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        newTaraSession.setLoginRequestInfo(loginRequestInfo);
        newTaraSession.setAllowedAuthMethods(getAllowedAuthenticationMethodsList(loginRequestInfo));
        log.info("Initialized authentication session: {}", newTaraSession);

        setLocale(language, newTaraSession);
        return "loginView";
    }

    private void setLocale(String language, TaraSession taraSession) {
        String locale = getUiLanguage(language, taraSession);
        RequestUtils.setLocale(locale);
    }

    private String getUiLanguage(String language, TaraSession taraSession) {
        if (isNotEmpty(language)) {
            return language;
        } else if (taraSession.getLoginRequestInfo().getOidcContext().getUiLocales() != null && taraSession.getLoginRequestInfo().getOidcContext().getUiLocales().get(0).matches("(et|en|ru)")) {
            return taraSession.getLoginRequestInfo().getOidcContext().getUiLocales().get(0);
        } else {
            return taraProperties.getDefaultLocale();
        }
    }

    private TaraSession.LoginRequestInfo fetchLoginRequestInfo(@RequestParam(name = "login_challenge") @Size(max = 50) @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed") String loginChallenge) {
        return doRequest(loginChallenge);
    }

    private LevelOfAssurance getRequestedAcr(TaraSession.LoginRequestInfo loginRequestInfo) {
        List<String> requestedAcr = loginRequestInfo.getOidcContext().getAcrValues();
        if (requestedAcr == null || requestedAcr.isEmpty())
            return null;
        LevelOfAssurance acr = LevelOfAssurance.findByAcrName(requestedAcr.get(0));
        Assert.notNull(acr, "Unsupported acr value requested by client: '" + requestedAcr.get(0) + "'");
        return acr;
    }

    private List<TaraScope> parseRequestedScopes(List<String> requestedScopes) {
        return requestedScopes != null ? requestedScopes.stream()
                .map(scope -> {
                    try {
                        return TaraScope.getScope(scope);
                    } catch (IllegalArgumentException e) {
                        log.warn("Unsupported scope value '{}', entry ignored!", scope);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList()) : new ArrayList<>();
    }

    private List<AuthenticationType> getAllowedAuthenticationMethodsList(TaraSession.LoginRequestInfo loginRequestInfo) {
        LevelOfAssurance requestedAcr = getRequestedAcr(loginRequestInfo);
        List<String> allowedRequestedScopes = getAllowedRequestedScopes(loginRequestInfo);
        List<TaraScope> requestedScopes = parseRequestedScopes(allowedRequestedScopes);
        return getAllowedAuthenticationTypes(requestedScopes, requestedAcr);
    }

    @NotNull
    private List<String> getAllowedRequestedScopes(TaraSession.LoginRequestInfo loginRequestInfo) {
        List<String> allowedRequestedScopes = new ArrayList<>();
        List<String> allowedScopes = Arrays.asList(loginRequestInfo.getClient().getScope().split(" "));
        for (String scope : loginRequestInfo.getRequestedScopes()) {
            if (allowedScopes.contains(scope))
                allowedRequestedScopes.add(scope);
            else
                log.warn("Requested scope value '{}' is not allowed, entry ignored!", scope);
        }
        return allowedRequestedScopes;
    }

    private List<AuthenticationType> getAllowedAuthenticationTypes(List<TaraScope> requestedScopes, LevelOfAssurance requestedLoa) {
        List<AuthenticationType> requestedAuthMethods = getRequestedAuthenticationMethodList(requestedScopes);
        List<AuthenticationType> allowedAuthenticationMethodsList = requestedAuthMethods.stream()
                .filter(this::isAuthenticationMethodEnabled)
                .filter(authMethod -> isAuthenticationMethodAllowedByRequestedLoa(requestedLoa, authMethod))
                .collect(Collectors.toList());

        if (isEmpty(allowedAuthenticationMethodsList))
            throw new BadRequestException(ErrorCode.NO_VALID_AUTHMETHODS_AVAILABLE, "No authentication methods match the requested level of assurance. Please check your authorization request");
        log.debug("List of authentication methods to display on login page: {}", allowedAuthenticationMethodsList);
        return allowedAuthenticationMethodsList;
    }

    private List<AuthenticationType> getRequestedAuthenticationMethodList(List<TaraScope> scopes) {
        List<AuthenticationType> clientRequestedAuthMethods = Arrays.stream(AuthenticationType.values())
                .filter(e -> scopes.contains(e.getScope())).collect(Collectors.toList());

        if (isEmpty(clientRequestedAuthMethods)) {
            return taraProperties.getDefaultAuthenticationMethods();
        } else {
            return clientRequestedAuthMethods;
        }
    }

    private boolean isAuthenticationMethodAllowedByRequestedLoa(LevelOfAssurance requestedLoa, AuthenticationType autMethod) {
        if (requestedLoa == null)
            return true;

        return isAllowedByRequestedLoa(requestedLoa, autMethod);
    }

    private boolean isAllowedByRequestedLoa(LevelOfAssurance requestedLoa, AuthenticationType authenticationMethod) {
        LevelOfAssurance authenticationMethodLoa = taraProperties.getAuthMethods().get(authenticationMethod).getLevelOfAssurance();
        boolean isAllowed = authenticationMethodLoa.ordinal() >= requestedLoa.ordinal();

        if (!isAllowed) {
            log.warn("Ignoring authentication method since it's level of assurance is lower than requested. Authentication method: {} with assigned LoA: {}, requested level of assurance: {}", authenticationMethod, authenticationMethodLoa, requestedLoa);
        }

        return isAllowed;
    }

    private boolean isAuthenticationMethodEnabled(AuthenticationType method) {
        return taraProperties.getAuthMethods().get(method).isEnabled();
    }

    private TaraSession.LoginRequestInfo doRequest(String loginChallenge) {
        String url = taraProperties.getHydraService().getLoginUrl() + "?login_challenge=" + loginChallenge;
        log.info("OIDC login GET request: " + url);
        long startTime = System.currentTimeMillis();
        try {
            ResponseEntity<TaraSession.LoginRequestInfo> response = hydraService.exchange(url, HttpMethod.GET, null, TaraSession.LoginRequestInfo.class);
            long duration = System.currentTimeMillis() - startTime;
            log.info("OIDC login response Code: " + response.getStatusCodeValue());
            log.info("OIDC login response Body: " + response.getBody());
            log.info("OIDC login request duration: " + duration + " ms");

            validateResponse(response.getBody(), loginChallenge);
            return response.getBody();
        } catch (HttpClientErrorException.NotFound e) {
            log.error(e.toString());
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
}
