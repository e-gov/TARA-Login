package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.Map;
import java.util.EnumSet;
import javax.cache.Cache;

import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.CONSENT_NOT_REQUIRED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WEBAUTHN_AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Validated
@Controller
public class AuthConsentController {
    private static final String REDIRECT_URL = "redirect_to";
    public static final String WEBAUTHN_USER_ID = "webauthn_user_id";
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());
    private static final EnumSet<TaraAuthenticationState> ALLOWED_STATES = EnumSet.of(AUTHENTICATION_SUCCESS, WEBAUTHN_AUTHENTICATION_SUCCESS, VERIFICATION_SUCCESS);

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraRestTemplate;

    @Autowired
    private RestTemplate eeidRestTemplate;

    @Autowired
    private StatisticsLogger statisticsLogger;

    @GetMapping(value = "/auth/consent", produces = MediaType.TEXT_HTML_VALUE)
    public String authConsent(@RequestParam(name = "consent_challenge") @Size(max = 50)
                              @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed") String consentChallenge, Model model,
                              @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);
        taraSession.setConsentChallenge(consentChallenge);
        if (taraSession.getLoginRequestInfo().getClient().getMetaData().isDisplayUserConsent()) {
            return createConsentView(model, taraSession);
        } else {
            String acceptConsentUrl;
            if (isWebauthnRequested(taraSession)) {
                acceptConsentUrl = authConfigurationProperties.getEeidService().getWebauthnAcceptConsentUrl();
                return webauthnAcceptConsent(taraSession, acceptConsentUrl, model);
            } else {
                acceptConsentUrl = authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + consentChallenge;
                return acceptConsent(taraSession, acceptConsentUrl, model);
            }
        }
    }

    @NotNull
    private String createConsentView(Model model, TaraSession taraSession) {
        model.addAttribute("subject", taraSession.getAuthenticationResult().getSubject());
        model.addAttribute("firstName", taraSession.getAuthenticationResult().getFirstName());
        model.addAttribute("lastName", taraSession.getAuthenticationResult().getLastName());
        if (shouldDateOfBirthBeDisplayed(taraSession))
            model.addAttribute("dateOfBirth", taraSession.getAuthenticationResult().getDateOfBirth());
        TaraSession.LegalPerson legalPerson = taraSession.getSelectedLegalPerson();
        if (legalPerson != null) {
            model.addAttribute("legalPersonName", legalPerson.getLegalName());
            model.addAttribute("legalPersonRegistryCode", legalPerson.getLegalPersonIdentifier());
        }
        if (shouldEmailBeDisplayed(taraSession))
            model.addAttribute("email", taraSession.getAuthenticationResult().getEmail());
        if (shouldPhoneNumberBeDisplayed(taraSession))
            model.addAttribute("phoneNumber", taraSession.getAuthenticationResult().getPhoneNumber());
        return "consentView";
    }

    private boolean shouldEmailBeDisplayed(TaraSession taraSession) {
        return taraSession.getAuthenticationResult().getEmail() != null;
    }

    private boolean shouldPhoneNumberBeDisplayed(TaraSession taraSession) {
        return taraSession.getAuthenticationResult().getPhoneNumber() != null;
    }

    private boolean shouldDateOfBirthBeDisplayed(TaraSession taraSession) {
        return taraSession.getAuthenticationResult().getDateOfBirth() != null;
    }

    @NotNull
    private String acceptConsent(TaraSession taraSession, String url, Model model) {
        AcceptConsentRequest acceptConsentRequest = AcceptConsentRequest.buildWithTaraSession(taraSession);

        requestLogger.logRequest(url, HttpMethod.PUT, acceptConsentRequest);
        var response = hydraRestTemplate.exchange(
                url,
                HttpMethod.PUT,
                new HttpEntity<>(acceptConsentRequest),
                new ParameterizedTypeReference<Map<String, String>>() {
                });
        requestLogger.logResponse(response);

        taraSession.setState(CONSENT_NOT_REQUIRED);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && response.getBody().get(REDIRECT_URL) != null) {
            statisticsLogger.log(taraSession);
            SessionUtils.invalidateSession();
            return "redirect:" + response.getBody().get(REDIRECT_URL);
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }

    @NotNull
    private String webauthnAcceptConsent(TaraSession taraSession, String url, Model model) {
        AcceptConsentRequest acceptConsentRequest = AcceptConsentRequest.buildWithTaraSession(taraSession);

        requestLogger.logRequest(url, HttpMethod.PUT, acceptConsentRequest);
        var response = eeidRestTemplate.exchange(
                url,
                HttpMethod.PUT,
                new HttpEntity<>(acceptConsentRequest),
                new ParameterizedTypeReference<Map<String, String>>() {
                });
        requestLogger.logResponse(response);

        taraSession.setState(CONSENT_NOT_REQUIRED);

        if (response.getStatusCode() == HttpStatus.CREATED && response.getBody() != null && response.getBody().get(WEBAUTHN_USER_ID) != null) {
            return createWebauthnRegisterView(model, taraSession, response.getBody().get(WEBAUTHN_USER_ID));
        } else {
            throw new IllegalStateException("Invalid EEID server response.");
        }
    }

    @NotNull
    private String createWebauthnRegisterView(Model model, TaraSession taraSession, String userId) {
        model.addAttribute("webauthn_user_id", userId);
        return "redirectToWebauthnRegister";
    }

    @NotNull
    private boolean isWebauthnRequested(TaraSession taraSession) {
        return (taraSession.getState().equals(AUTHENTICATION_SUCCESS) || taraSession.getState().equals(VERIFICATION_SUCCESS))
            && taraSession.getLoginRequestInfo().getRequestedScopes().contains(TaraScope.WEBAUTHN.getFormalName());
    }
}
