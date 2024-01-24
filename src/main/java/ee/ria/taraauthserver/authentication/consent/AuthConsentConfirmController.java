package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import jakarta.validation.constraints.Pattern;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.util.HashMap;
import java.util.Map;

import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.CONSENT_GIVEN;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.CONSENT_NOT_GIVEN;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_CONSENT_PROCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Validated
@Controller
public class AuthConsentConfirmController {
    public static final String REDIRECT_TO = "redirect_to";
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraRestTemplate;

    @Autowired
    private StatisticsLogger statisticsLogger;

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
        Map<String, String> requestParams = new HashMap<>();
        requestParams.put("error", "user_cancel");
        requestParams.put("error_debug", "Consent not given. User canceled the authentication process.");
        requestParams.put("error_description", "Consent not given. User canceled the authentication process.");
        return getRedirectView(taraSession, CONSENT_NOT_GIVEN, requestUrl, requestParams);
    }

    @NotNull
    private RedirectView acceptConsent(TaraSession taraSession) {
        String requestUrl = authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + taraSession.getConsentChallenge();
        AcceptConsentRequest acceptConsentRequest = AcceptConsentRequest.buildWithTaraSession(taraSession);
        return getRedirectView(taraSession, CONSENT_GIVEN, requestUrl, acceptConsentRequest);
    }

    @NotNull
    private RedirectView getRedirectView(TaraSession taraSession, TaraAuthenticationState taraSessionState, String requestUrl, Object requestBody) {

        requestLogger.logRequest(requestUrl, HttpMethod.PUT, requestBody);
        var response = hydraRestTemplate.exchange(
                requestUrl,
                HttpMethod.PUT,
                new HttpEntity<>(requestBody),
                new ParameterizedTypeReference<Map<String, String>>() {
                });
        requestLogger.logResponse(response);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && response.getBody().get(REDIRECT_TO) != null) {
            taraSession.setState(taraSessionState);
            statisticsLogger.log(taraSession);
            SessionUtils.invalidateSession();
            return new RedirectView(response.getBody().get(REDIRECT_TO));
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }
}
