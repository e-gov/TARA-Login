package ee.ria.taraauthserver.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.TaraScope;
import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.utils.SessionUtils;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpSession;
import java.util.List;

import static ee.ria.taraauthserver.error.ErrorMessages.SESSION_STATE_INVALID;
import static ee.ria.taraauthserver.session.AuthState.*;

@Slf4j
@Validated
@Controller
class AuthAcceptController {

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

    @GetMapping("/auth/accept")
    public RedirectView authAccept(HttpSession session) {

        AuthSession authSession = SessionUtils.getAuthSession();

        if (isLegalPersonAttributesRequested(authSession)) {
            return new RedirectView("/auth/legal_person/init");
        }

        if (!List.of(LEGAL_PERSON_AUTHENTICATION_COMPLETED, NATURAL_PERSON_AUTHENTICATION_COMPLETED).contains(authSession.getState()))
            throw new BadRequestException(SESSION_STATE_INVALID, String.format("Session in invalid state: '%s'. Expected state: %s", authSession.getState(), List.of(LEGAL_PERSON_AUTHENTICATION_COMPLETED, NATURAL_PERSON_AUTHENTICATION_COMPLETED)));

        String url = authConfigurationProperties.getHydraService().getAcceptLoginUrl() + "?login_challenge=" + authSession.getLoginRequestInfo().getChallenge();
        ResponseEntity<LoginAcceptResponseBody> response = hydraService.exchange(url, HttpMethod.PUT, createRequestBody(authSession), LoginAcceptResponseBody.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody().getRedirectUrl() != null) {
            authSession.setState(AUTHENTICATION_SUCCESS);
            SessionUtils.updateSession(authSession);
            log.info("accepted session: " + authSession);
            return new RedirectView(response.getBody().getRedirectUrl());
        } else {
            throw new IllegalStateException("Internal server error");
        }
    }

    private HttpEntity<LoginAcceptRequestBody> createRequestBody(AuthSession authSession) {
        log.info("authsession: " + authSession.toString());
        AuthSession.AuthenticationResult authenticationResult = authSession.getAuthenticationResult();
        Assert.notNull(authenticationResult.getAcr(), "Mandatory 'acr' value is missing from authentication!");
        Assert.notNull(authenticationResult.getSubject(), "Mandatory 'subject' value is missing from authentication!");
        return new HttpEntity<>(new LoginAcceptRequestBody(
                false,
                authenticationResult.getAcr().getAcrName(),
                authenticationResult.getSubject()));
    }

    private boolean isLegalPersonAttributesRequested(AuthSession authSession) {
        return authSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED && authSession.getLoginRequestInfo().getRequestedScopes().contains(TaraScope.LEGALPERSON.getFormalName());
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
