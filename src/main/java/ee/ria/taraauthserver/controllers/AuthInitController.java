package ee.ria.taraauthserver.controllers;


import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.AuthenticationType;
import ee.ria.taraauthserver.config.LevelOfAssurance;
import ee.ria.taraauthserver.config.TaraScope;
import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.ConstraintViolation;
import javax.validation.Validator;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.*;
import java.util.stream.Collectors;

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

        AuthSession authSession = initAuthSession(loginChallenge);

        setLocale(language, authSession);

        return "loginView";
    }

    private AuthSession initAuthSession(String loginChallenge) {
        HttpSession httpSession = resetHttpSession();

        AuthSession.LoginRequestInfo loginRequestInfo = fetchLoginRequestInfo(loginChallenge);

        AuthSession newAuthSession = getAuthSession(loginRequestInfo);
        httpSession.setAttribute("session", newAuthSession);
        log.info("created session: " + newAuthSession);
        return newAuthSession;
    }

    private void setLocale(String language, AuthSession authSession) {
        String locale = getUiLanguage(language, authSession);
        RequestUtils.setLocale(locale);
    }

    private AuthSession getAuthSession(AuthSession.LoginRequestInfo loginRequestInfo) {
        AuthSession newAuthSession = new AuthSession();
        newAuthSession.setState(AuthState.INIT_AUTH_PROCESS);
        newAuthSession.setLoginRequestInfo(loginRequestInfo);
        newAuthSession.setAllowedAuthMethods(getAllowedAuthenticationMethodsList(loginRequestInfo));
        return newAuthSession;
    }

    private HttpSession resetHttpSession() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            log.warn("session has been reset");
        }

        session = request.getSession(true);
        return session;
    }

    private String getUiLanguage(String language, AuthSession authSession) {
        if (isNotEmpty(language)) {
            return language;
        } else if (authSession.getLoginRequestInfo().getOidcContext().getUiLocales() != null && authSession.getLoginRequestInfo().getOidcContext().getUiLocales().get(0).matches("(et|en|ru)")) {
            return authSession.getLoginRequestInfo().getOidcContext().getUiLocales().get(0);
        } else {
            return taraProperties.getDefaultLocale();
        }
    }

    private AuthSession.LoginRequestInfo fetchLoginRequestInfo(@RequestParam(name = "login_challenge") @Size(max = 50) @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed") String loginChallenge) {
        String url = taraProperties.getHydraService().getLoginUrl() + "?login_challenge=" + loginChallenge;
        return doRequest(url);
    }

    private LevelOfAssurance getRequestedAcr(AuthSession.LoginRequestInfo loginRequestInfo) {
        List<String> requestedAcr = loginRequestInfo.getOidcContext().getAcrValues();
        if(requestedAcr == null || requestedAcr.isEmpty())
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

    private List<AuthenticationType> getAllowedAuthenticationMethodsList(AuthSession.LoginRequestInfo loginRequestInfo) {
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
            return  taraProperties.getDefaultAuthenticationMethods();
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
            log.warn("Ignoring authentication method since it's level of assurance is lower than requested. Authentication method: {} with assigned LoA: {}, requested level of assurance: {}", authenticationMethod, authenticationMethodLoa, requestedLoa );
        }

        return isAllowed;
    }

    private boolean isAuthenticationMethodEnabled(AuthenticationType method) {
        return taraProperties.getAuthMethods().get(method).isEnabled();
    }

    private AuthSession.LoginRequestInfo doRequest(String url) {
        long startTime = System.currentTimeMillis();
        ResponseEntity<AuthSession.LoginRequestInfo> response = hydraService.exchange(url, HttpMethod.GET, null, AuthSession.LoginRequestInfo.class);
        long duration = System.currentTimeMillis() - startTime;
        log.info("Response Code: " + response.getStatusCodeValue());
        log.info("Response Body: " + response.getBody());
        log.info("request duration: " + duration + " ms");

        validateResponse(response.getBody());
        return response.getBody();
    }

    private void validateResponse(AuthSession.LoginRequestInfo response) {
        Set<ConstraintViolation<AuthSession.LoginRequestInfo>> constraintViolations = validator.validate(response);
        if (!constraintViolations.isEmpty())
            throw new IllegalStateException("Invalid hydra response: " + getConstraintViolationsAsString(constraintViolations));
    }

    private static String getConstraintViolationsAsString(Set<? extends ConstraintViolation<?>> constraintViolations) {
        return constraintViolations.stream()
                .map(cv -> cv == null ? "null" : cv.getPropertyPath() + ": " + cv.getMessage())
                .collect(Collectors.joining(", "));
    }

}
