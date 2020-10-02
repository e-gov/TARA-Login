package ee.ria.taraauthserver.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpSession;

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

        AuthSession authSession = (AuthSession) session.getAttribute("session");

        log.info("accepted session: " + authSession);

        if (authSession == null)
            throw new IllegalStateException("Internal server error");
        if (authSession.getState() != AuthState.AUTHENTICATION_SUCCESS)
            throw new BadRequestException("Authentication state must be " + AuthState.AUTHENTICATION_SUCCESS);

        String url = authConfigurationProperties.getHydraService().getAcceptLoginUrl() + "?login_challenge=" + authSession.getLoginRequestInfo().getChallenge();
        ResponseEntity<LoginAcceptResponseBody> response = hydraService.exchange(url, HttpMethod.PUT, createRequestBody(authSession), LoginAcceptResponseBody.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody().getRedirectUrl() != null)
            return new RedirectView(response.getBody().getRedirectUrl());
        else
            throw new IllegalStateException("Internal server error");
    }

    private HttpEntity<LoginAcceptRequestBody> createRequestBody(AuthSession authSession) {
        log.info("authsession: " + authSession.toString());
        AuthSession.AuthenticationResult authenticationResult = authSession.getAuthenticationResult();
        return new HttpEntity<>(new LoginAcceptRequestBody(
                false,
                authenticationResult.getAcr().getAcrName(),
                authenticationResult.getSubject()));
    }

    @AllArgsConstructor
    @NoArgsConstructor
    @ToString
    static class LoginAcceptRequestBody {

        @JsonProperty("remember")
        boolean remember;
        @JsonProperty("acr")
        String acr;
        @JsonProperty("subject")
        String subject;
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @ToString
    static class LoginAcceptResponseBody {

        @JsonProperty("redirect_to")
        String redirectUrl;
    }
}
