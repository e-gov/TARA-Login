package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.util.HashMap;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.CONSENT_GIVEN;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.CONSENT_NOT_GIVEN;

@Validated
@Controller
public class AuthConsentConfirmController {

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

    @PostMapping(value = "/auth/consent/confirm", produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView authConsentConfirm(@RequestParam(name = "consent_given") boolean consentGiven) {

        TaraSession taraSession = SessionUtils.getAuthSessionInState(TaraAuthenticationState.INIT_CONSENT_PROCESS);

        if (consentGiven) {
            return acceptConsent(taraSession);
        } else {
            return rejectConsent(taraSession);
        }
    }

    @NotNull
    private RedirectView rejectConsent(TaraSession taraSession) {
        String url = authConfigurationProperties.getHydraService().getRejectConsentUrl() + "?consent_challenge=" + taraSession.getConsentChallenge();
        Map<String, String> map = new HashMap<>();
        map.put("error", "request_denied");
        HttpEntity<Map> entity = new HttpEntity<>(map);
        ResponseEntity<Map> response = hydraService.exchange(url, HttpMethod.PUT, entity, Map.class);
        if (response.getStatusCode() == HttpStatus.OK && response.getBody().get("redirect_to") != null) {
            taraSession.setState(CONSENT_GIVEN);
            SessionUtils.updateSession(taraSession);
            return new RedirectView(response.getBody().get("redirect_to").toString());
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }

    @NotNull
    private RedirectView acceptConsent(TaraSession taraSession) {
        String url = authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + taraSession.getConsentChallenge();
        HttpEntity<ConsentUtils.AcceptConsentRequest> request = ConsentUtils.createRequestBody(taraSession);
        ResponseEntity<Map> response = hydraService.exchange(url, HttpMethod.PUT, request, Map.class);
        if (response.getStatusCode() == HttpStatus.OK && response.getBody().get("redirect_to") != null) {
            taraSession.setState(CONSENT_NOT_GIVEN);
            SessionUtils.updateSession(taraSession);
            return new RedirectView(response.getBody().get("redirect_to").toString());
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }
}
