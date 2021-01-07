package ee.ria.taraauthserver.authentication;


import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.TaraScope;
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
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
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

    @Autowired
    private AuthConfigurationProperties taraProperties;

    @Autowired
    private RestTemplate hydraService;

    @Autowired
    private Validator validator;

    @GetMapping(value = "/auth/init", produces = MediaType.TEXT_HTML_VALUE)
    public String authInit(
            @RequestParam(name = "login_challenge") @Size(max = 50)
            @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed")
                    String loginChallenge,
            @RequestParam(name = "lang", required = false)
            @Pattern(regexp = "(et|en|ru)", message = "supported values are: 'et', 'en', 'ru'")
                    String language) {

        TaraSession taraSession = initAuthSession(loginChallenge);

        setLocale(language, taraSession);

        return "loginView";
    }

    private TaraSession initAuthSession(String loginChallenge) {
        HttpSession httpSession = resetHttpSession();
        TaraSession.LoginRequestInfo loginRequestInfo = fetchLoginRequestInfo(loginChallenge);

        TaraSession newTaraSession = new TaraSession(httpSession.getId());
        newTaraSession.setState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        newTaraSession.setLoginRequestInfo(loginRequestInfo);
        newTaraSession.setAllowedAuthMethods(getAllowedAuthenticationMethodsList(loginRequestInfo));
        httpSession.setAttribute(TARA_SESSION, newTaraSession);
        log.info("Created session: {}", newTaraSession);
        return newTaraSession;
    }

    private void setLocale(String language, TaraSession taraSession) {
        String locale = getUiLanguage(language, taraSession);
        RequestUtils.setLocale(locale);
    }

    private HttpSession resetHttpSession() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpSession session = request.getSession(false);
        if (session != null) {
            log.warn("Session '{}' has been reset", session.getId());
            session.invalidate();
        }

        session = request.getSession(true);
        return session;
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
        String url = taraProperties.getHydraService().getLoginUrl() + "?login_challenge=" + loginChallenge;
        return doRequest(url);
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
        List<TaraScope> requestedScopes = parseRequestedScopes(loginRequestInfo.getRequestedScopes());
        return getAllowedAuthenticationTypes(requestedScopes, requestedAcr);
    }

    private List<AuthenticationType> getAllowedAuthenticationTypes(List<TaraScope> requestedScopes, LevelOfAssurance requestedLoa) {
        List<AuthenticationType> requestedAuthMethods = getRequestedAuthenticationMethodList(requestedScopes);
        List<AuthenticationType> allowedAuthenticationMethodsList = requestedAuthMethods.stream()
                .filter(this::isAuthenticationMethodEnabled)
                .filter(autMethod -> isAuthenticationMethodAllowedByRequestedLoa(requestedLoa, autMethod))
                .collect(Collectors.toList());

        if (isEmpty(allowedAuthenticationMethodsList))
            throw new BadRequestException("No authentication methods match the requested level of assurance. Please check your authorization request");
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

    private TaraSession.LoginRequestInfo doRequest(String url) {
        long startTime = System.currentTimeMillis();
        ResponseEntity<TaraSession.LoginRequestInfo> response = hydraService.exchange(url, HttpMethod.GET, null, TaraSession.LoginRequestInfo.class);
        long duration = System.currentTimeMillis() - startTime;
        log.info("Response Code: " + response.getStatusCodeValue());
        log.info("Response Body: " + response.getBody());
        log.info("request duration: " + duration + " ms");

        validateResponse(response.getBody());
        return response.getBody();
    }

    private void validateResponse(TaraSession.LoginRequestInfo response) {
        Set<ConstraintViolation<TaraSession.LoginRequestInfo>> constraintViolations = validator.validate(response);
        if (!constraintViolations.isEmpty())
            throw new IllegalStateException("Invalid hydra response: " + getConstraintViolationsAsString(constraintViolations));
    }

    private static String getConstraintViolationsAsString(Set<? extends ConstraintViolation<?>> constraintViolations) {
        return constraintViolations.stream()
                .map(cv -> cv == null ? "null" : cv.getPropertyPath() + ": " + cv.getMessage())
                .collect(Collectors.joining(", "));
    }

}
