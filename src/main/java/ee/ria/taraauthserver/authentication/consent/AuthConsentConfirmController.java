package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.constraints.Pattern;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Validated
@Controller
public class AuthConsentConfirmController {
    public static final String REDIRECT_TO = "redirect_to";

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

    @PostMapping(value = "/auth/consent/confirm", produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView authConsentConfirm(
            @RequestParam(name = "consent_given")
            @Pattern(regexp = "(true|false)", message = "supported values are: 'true', 'false'") String consentGiven,
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_CONSENT_PROCESS);
        if (consentGiven.equals("true")) {
            return acceptConsent(taraSession);
        } else {
            return rejectConsent(taraSession);
        }
    }

    @NotNull
    private RedirectView rejectConsent(TaraSession taraSession) {
        String requestUrl = authConfigurationProperties.getHydraService().getRejectConsentUrl() + "?consent_challenge=" + taraSession.getConsentChallenge();
        log.info(append("url.full", requestUrl), "OIDC reject consent request for challenge: {}",
                value("tara.session.consent_challenge", taraSession.getConsentChallenge()));
        Map<String, String> requestParams = new HashMap<>();
        requestParams.put("error", "user_cancel");
        requestParams.put("error_debug", "Consent not given. User canceled the authentication process.");
        requestParams.put("error_description", "Consent not given. User canceled the authentication process.");
        HttpEntity<Map<String, String>> requestEntity = new HttpEntity<>(requestParams);
        return getRedirectView(taraSession, CONSENT_NOT_GIVEN, requestUrl, requestEntity);
    }

    @NotNull
    private RedirectView acceptConsent(TaraSession taraSession) {
        String requestUrl = authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + taraSession.getConsentChallenge();
        AcceptConsentRequest acceptConsentRequest = AcceptConsentRequest.buildWithTaraSession(taraSession);
        log.info(append("tara.session.accept_consent_request", acceptConsentRequest).and(append("url.full", requestUrl)),
                "OIDC accept consent request for challenge: {}", value("tara.session.consent_challenge", taraSession.getConsentChallenge()));
        return getRedirectView(taraSession, CONSENT_GIVEN, requestUrl, new HttpEntity<>(acceptConsentRequest));
    }

    @NotNull
    private RedirectView getRedirectView(TaraSession taraSession, TaraAuthenticationState taraSessionState, String requestUrl, HttpEntity<?> requestEntity) {
        ResponseEntity<Map<String, String>> response = hydraService.exchange(requestUrl, HttpMethod.PUT, requestEntity, new ParameterizedTypeReference<>() {
        });
        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && response.getBody().get(REDIRECT_TO) != null) {
            taraSession.setState(taraSessionState);
            SessionUtils.invalidateSession();
            return new RedirectView(response.getBody().get(REDIRECT_TO));
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }
}
