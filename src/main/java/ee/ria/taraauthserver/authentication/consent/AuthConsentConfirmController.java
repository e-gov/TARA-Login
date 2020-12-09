package ee.ria.taraauthserver.authentication.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;

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
            String url = authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + taraSession.getConsentChallenge();
            HttpEntity<AcceptConsentRequest> request = createRequestBody(taraSession);

            ResponseEntity<Map> response = hydraService.exchange(url, HttpMethod.PUT, request, Map.class);
            if (response.getStatusCode() == HttpStatus.OK && response.getBody().get("redirect_to") != null) {
                taraSession.setState(AUTHENTICATION_SUCCESS);
                SessionUtils.updateSession(taraSession);
                return new RedirectView(response.getBody().get("redirect_to").toString());
            } else {
                throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
            }
        } else {
            String url = authConfigurationProperties.getHydraService().getRejectConsentUrl() + "?consent_challenge=" + taraSession.getConsentChallenge();
            Map<String, String> map = new HashMap<>();
            map.put("error", "request_denied");

            HttpEntity<Map> entity = new HttpEntity<>(map);
            ResponseEntity<Map> response = hydraService.exchange(url, HttpMethod.PUT, entity, Map.class);
            if (response.getStatusCode() == HttpStatus.OK && response.getBody().get("redirect_to") != null) {
                taraSession.setState(AUTHENTICATION_SUCCESS);
                SessionUtils.updateSession(taraSession);
                return new RedirectView(response.getBody().get("redirect_to").toString());
            } else {
                throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
            }
        }
    }

    @NotNull
    private HttpEntity<AcceptConsentRequest> createRequestBody(TaraSession taraSession) {
        AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();
        HttpEntity<AcceptConsentRequest> request = new HttpEntity<>(acceptConsentRequest);

        Map<String, Object> profileAttributes = new LinkedHashMap<>();

        addProfile_attributes(profileAttributes, taraSession);

        acceptConsentRequest.setSession(new AcceptConsentRequest.LoginSession(
                profileAttributes
        ));
        profileAttributes.put("state", getStateParameterValue(taraSession));
        profileAttributes.put("amr", taraSession.getAuthenticationResult().getAmr());
        return request;
    }

    private void addLegalPersonAttributes(Map<String, Object> attributes, TaraSession.LegalPerson legalPerson) {
        Map<String, Object> legalPersonAttributes = Map.of(
                "name", legalPerson.getLegalName(),
                "registry_code", legalPerson.getLegalPersonIdentifier()
        );
        attributes.put("legal_person", legalPersonAttributes);
    }

    private void addProfile_attributes(Map<String, Object> attributes, TaraSession taraSession) {
        Map<String, Object> profileAttributes = new LinkedHashMap<>();
        profileAttributes.put("family_name", taraSession.getAuthenticationResult().getLastName());
        profileAttributes.put("given_name", taraSession.getAuthenticationResult().getFirstName());
        profileAttributes.put("date_of_birth", taraSession.getAuthenticationResult().getDateOfBirth().toString());
        profileAttributes.put("acr", taraSession.getAuthenticationResult().getAcr());
        TaraSession.LegalPerson legalPerson = taraSession.getSelectedLegalPerson();
        if (legalPerson != null) {
            addLegalPersonAttributes(profileAttributes, legalPerson);
        }
        attributes.put("profile_attributes", profileAttributes);
    }

    private String getStateParameterValue(TaraSession taraSession) {
        URL oidcAuthRequestUrl = (taraSession).getLoginRequestInfo().getUrl();
        Assert.notNull(oidcAuthRequestUrl, "OIDC authentication URL cannot be null!");
        String state = getQueryMap(oidcAuthRequestUrl.getQuery()).get("state");
        Assert.notNull(state, "State paremeter is mandatory and cannot be null!");
        return state;
    }

    public static Map<String, String> getQueryMap(String query) {
        String[] params = query.split("&");
        Map<String, String> map = new HashMap<>();

        for (String param : params) {
            String name = param.split("=")[0];
            String value = param.split("=")[1];
            map.put(name, value);
        }
        return map;
    }

    @Data
    public static class AcceptConsentRequest {
        @JsonProperty("remember")
        boolean remember = false;
        @JsonProperty("session")
        LoginSession session;
        @JsonProperty("grant_scope")
        String[] grantScope = new String[]{"openid", "mid"};

        @Data
        @RequiredArgsConstructor
        public static class LoginSession {
            @JsonProperty("id_token")
            private final Map idToken;
        }
    }
}
