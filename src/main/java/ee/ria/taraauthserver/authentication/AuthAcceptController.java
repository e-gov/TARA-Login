package ee.ria.taraauthserver.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.util.EnumSet;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.EnumSet.of;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.springframework.http.HttpMethod.PUT;

@Slf4j
@Validated
@Controller
class AuthAcceptController {
    private static final EnumSet<TaraAuthenticationState> ALLOWED_STATES = of(AUTHENTICATION_SUCCESS, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED);
    private static final EnumSet<TaraAuthenticationState> OIDC_AUTH_ACCEPT_STATES = of(NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED);

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

    @PostMapping("/auth/accept")
    public RedirectView authAccept(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);

        if (OIDC_AUTH_ACCEPT_STATES.contains(taraSession.getState())) {
            if (isLegalPersonAttributesRequested(taraSession)) {
                return new RedirectView("/auth/legalperson/init");
            }
            return acceptLoginRequest(taraSession);
        } else if (taraSession.getState() == AUTHENTICATION_SUCCESS && taraSession.getLoginRequestInfo().getLoginVerifierRedirectUrl() != null) {
            return new RedirectView(taraSession.getLoginRequestInfo().getLoginVerifierRedirectUrl());
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }

    private RedirectView acceptLoginRequest(TaraSession taraSession) {
        TaraSession.LoginRequestInfo loginRequestInfo = taraSession.getLoginRequestInfo();
        String url = authConfigurationProperties.getHydraService().getAcceptLoginUrl() + "?login_challenge=" + loginRequestInfo.getChallenge();
        log.info(append("url.full", url), "OIDC login accept request for challenge: {}", value("tara.session.login_request_info.challenge", loginRequestInfo.getChallenge()));
        ResponseEntity<LoginAcceptResponseBody> response = hydraService.exchange(url, PUT, createRequestBody(taraSession), LoginAcceptResponseBody.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && response.getBody().getRedirectUrl() != null) {
            taraSession.setState(AUTHENTICATION_SUCCESS);
            String loginVerifierRedirectUrl = response.getBody().getRedirectUrl();
            loginRequestInfo.setLoginVerifierRedirectUrl(loginVerifierRedirectUrl);
            loginRequestInfo.setLoginChallengeExpired(true);
            return new RedirectView(loginVerifierRedirectUrl);
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }

    private HttpEntity<LoginAcceptRequestBody> createRequestBody(TaraSession taraSession) {
        TaraSession.AuthenticationResult authenticationResult = taraSession.getAuthenticationResult();
        Assert.notNull(authenticationResult.getAcr(), "Mandatory 'acr' value is missing from authentication!");
        Assert.notNull(authenticationResult.getSubject(), "Mandatory 'subject' value is missing from authentication!");
        return new HttpEntity<>(new LoginAcceptRequestBody(
                false,
                authenticationResult.getAcr().getAcrName(),
                authenticationResult.getSubject()));
    }

    private boolean isLegalPersonAttributesRequested(TaraSession taraSession) {
        return taraSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED && taraSession.getLoginRequestInfo().getRequestedScopes().contains(TaraScope.LEGALPERSON.getFormalName());
    }

    @RequiredArgsConstructor
    static class LoginAcceptRequestBody {
        @JsonProperty("remember")
        private final boolean remember;
        @JsonProperty("acr")
        private final String acr;
        @JsonProperty("subject")
        private final String subject;
    }

    @Data
    static class LoginAcceptResponseBody {
        @JsonProperty("redirect_to")
        private String redirectUrl;
    }
}
