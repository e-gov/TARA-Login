package ee.ria.taraauthserver.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpSession;
import java.util.List;

import static ee.ria.taraauthserver.error.ErrorTranslationCodes.SESSION_STATE_INVALID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;

@Slf4j
@Validated
@Controller
class AuthAcceptController {

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

    @PostMapping("/auth/accept")
    public RedirectView authAccept(HttpSession session) {

        TaraSession taraSession = SessionUtils.getAuthSession();

        if (isLegalPersonAttributesRequested(taraSession)) {
            return new RedirectView("/auth/legal_person/init");
        }

        if (!List.of(LEGAL_PERSON_AUTHENTICATION_COMPLETED, NATURAL_PERSON_AUTHENTICATION_COMPLETED).contains(taraSession.getState()))
            throw new BadRequestException(SESSION_STATE_INVALID, String.format("Session in invalid state: '%s'. Expected state: %s", taraSession.getState(), List.of(LEGAL_PERSON_AUTHENTICATION_COMPLETED, NATURAL_PERSON_AUTHENTICATION_COMPLETED)));

        String url = authConfigurationProperties.getHydraService().getAcceptLoginUrl() + "?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge();
        ResponseEntity<LoginAcceptResponseBody> response = hydraService.exchange(url, HttpMethod.PUT, createRequestBody(taraSession), LoginAcceptResponseBody.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody().getRedirectUrl() != null) {
            taraSession.setState(AUTHENTICATION_SUCCESS);
            SessionUtils.updateSession(taraSession);
            log.info("accepted session: " + taraSession);
            return new RedirectView(response.getBody().getRedirectUrl());
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }

    private HttpEntity<LoginAcceptRequestBody> createRequestBody(TaraSession taraSession) {
        log.info("authsession: " + taraSession.toString());
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
