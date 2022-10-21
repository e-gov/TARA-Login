package ee.ria.taraauthserver.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.util.EnumSet;

import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_STATUS_CANCELED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.lang.String.format;
import static java.util.EnumSet.of;

@Validated
@Controller
class AuthAcceptController {
    private static final EnumSet<TaraAuthenticationState> ALLOWED_STATES = of(AUTHENTICATION_SUCCESS, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED);
    private static final EnumSet<TaraAuthenticationState> OIDC_AUTH_ACCEPT_STATES = of(NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED);
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraRestTemplate;

    @PostMapping("/auth/accept")
    public RedirectView authAccept(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        } else if (taraSession.getState().equals(POLL_MID_STATUS_CANCELED) || taraSession.getState().equals(POLL_SID_STATUS_CANCELED)) {
            return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge());
        } else if (!ALLOWED_STATES.contains(taraSession.getState())) {
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, format("Invalid authentication state: '%s', expected one of: %s", taraSession.getState(), ALLOWED_STATES));
        }

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
        LoginAcceptRequestBody requestBody = createRequestBody(taraSession);

        requestLogger.logRequest(url, HttpMethod.PUT, requestBody);
        var response = hydraRestTemplate.exchange(
                url,
                HttpMethod.PUT,
                new HttpEntity<>(requestBody),
                LoginAcceptResponseBody.class);
        requestLogger.logResponse(response);

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

    private LoginAcceptRequestBody createRequestBody(TaraSession taraSession) {
        TaraSession.AuthenticationResult authenticationResult = taraSession.getAuthenticationResult();
        Assert.notNull(authenticationResult.getAcr(), "Mandatory 'acr' value is missing from authentication!");
        Assert.notNull(authenticationResult.getSubject(), "Mandatory 'subject' value is missing from authentication!");
        return new LoginAcceptRequestBody(
                false,
                authenticationResult.getAcr().getAcrName(),
                authenticationResult.getSubject());
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
