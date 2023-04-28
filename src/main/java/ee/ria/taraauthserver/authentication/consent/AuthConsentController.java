package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
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
import javax.cache.Cache;

import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_CONSENT_PROCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Validated
@Controller
public class AuthConsentController {
    private static final String REDIRECT_URL = "redirect_to";
    public static final String WEBAUTHN_USER_ID = "webauthn_user_id";
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraRestTemplate;

    @Autowired
    private StatisticsLogger statisticsLogger;

    @GetMapping(value = "/auth/consent", produces = MediaType.TEXT_HTML_VALUE)
    public String authConsent(@RequestParam(name = "consent_challenge") @Size(max = 50)
                              @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed") String consentChallenge, Model model,
                              @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, AUTHENTICATION_SUCCESS);
        taraSession.setConsentChallenge(consentChallenge);
        if (taraSession.getLoginRequestInfo().getClient().getMetaData().isDisplayUserConsent()) {
            taraSession.setState(INIT_CONSENT_PROCESS);
            return createConsentView(model, taraSession);
        } else {
            taraSession.setState(TaraAuthenticationState.CONSENT_NOT_REQUIRED);
            String acceptConsentUrl = webauthnRequested(taraSession.getLoginRequestInfo()) 
                                    ? authConfigurationProperties.getEeidService().getAcceptConsentUrl() 
                                    : authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + consentChallenge;
            return acceptConsent(consentChallenge, taraSession, acceptConsentUrl, model);
        }
    }

    @NotNull
    private String createConsentView(Model model, TaraSession taraSession) {
        model.addAttribute("subject", taraSession.getAuthenticationResult().getSubject());
        model.addAttribute("firstName", taraSession.getAuthenticationResult().getFirstName());
        model.addAttribute("lastName", taraSession.getAuthenticationResult().getLastName());
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
        return taraSession.isEmailScopeRequested() && taraSession.getAuthenticationResult().getEmail() != null;
    }

    private boolean shouldPhoneNumberBeDisplayed(TaraSession taraSession) {
        return taraSession.isPhoneNumberScopeRequested() && taraSession.getAuthenticationResult().getPhoneNumber() != null;
    }

    @NotNull
    private String acceptConsent(String consentChallenge, TaraSession taraSession, String url, Model model) {
        AcceptConsentRequest acceptConsentRequest = AcceptConsentRequest.buildWithTaraSession(taraSession);

        requestLogger.logRequest(url, HttpMethod.PUT, acceptConsentRequest);
        var response = hydraRestTemplate.exchange(
                url,
                HttpMethod.PUT,
                new HttpEntity<>(acceptConsentRequest),
                new ParameterizedTypeReference<Map<String, String>>() {
                });
        requestLogger.logResponse(response);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && response.getBody().get(REDIRECT_URL) != null) {
            statisticsLogger.log(taraSession);
            SessionUtils.invalidateSession();
            return "redirect:" + response.getBody().get(REDIRECT_URL);
        } else if (response.getStatusCode() == HttpStatus.ACCEPTED) {
            String acceptConsentUrl = authConfigurationProperties.getHydraService().getAcceptConsentUrl();
            return acceptConsent(consentChallenge, taraSession, acceptConsentUrl + "?consent_challenge=" + consentChallenge, model);
        } else if (response.getStatusCode() == HttpStatus.CREATED && response.getBody() != null && response.getBody().get(WEBAUTHN_USER_ID) != null) {
            return createWebauthnRegisterView(model, taraSession, response.getBody().get(WEBAUTHN_USER_ID));
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }

    @NotNull
    private String createWebauthnRegisterView(Model model, TaraSession taraSession, String userId) {
        model.addAttribute("webauthn_user_id", userId);
        return "redirectToWebauthnRegister";
    }

    @NotNull
    private boolean webauthnRequested(TaraSession.LoginRequestInfo loginRequestInfo) {
        return loginRequestInfo.getRequestedScopes().contains("webauthn");
    }
}
