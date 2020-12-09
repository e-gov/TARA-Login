package ee.ria.taraauthserver.authentication.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_CONSENT_PROCESS;

@Slf4j
@Validated
@Controller
public class AuthConsentController {

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

    @GetMapping(value = "/consent", produces = MediaType.TEXT_HTML_VALUE)
    public String authAccept(@RequestParam(name = "consent_challenge") @Size(max = 50)
                             @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed")
                                     String consentChallenge, Model model) {

        TaraSession taraSession = SessionUtils.getAuthSessionInState(TaraAuthenticationState.AUTHENTICATION_SUCCESS);

        if (taraSession.getLoginRequestInfo().getClient().getMetaData().isDisplay_user_consent()) {
            taraSession.setState(INIT_CONSENT_PROCESS);
            taraSession.setConsentChallenge(consentChallenge);
            SessionUtils.updateSession(taraSession);
            model.addAttribute("idCode", taraSession.getAuthenticationResult().getIdCode());
            model.addAttribute("firstName", taraSession.getAuthenticationResult().getFirstName());
            model.addAttribute("lastName", taraSession.getAuthenticationResult().getLastName());
            model.addAttribute("dateOfBirth", taraSession.getAuthenticationResult().getDateOfBirth());
            return "consentView";
        } else {
            taraSession.setState(TaraAuthenticationState.CONSENT_NOT_REQUIRED);
            SessionUtils.updateSession(taraSession);
            HttpEntity<AcceptConsentRequest> request = createRequestBody(taraSession);
            String url = authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + consentChallenge;

            ResponseEntity<Map> response = hydraService.exchange(url, HttpMethod.PUT, request, Map.class);
            if (response.getStatusCode() == HttpStatus.OK && response.getBody().get("redirect_to") != null) {
                taraSession.setState(AUTHENTICATION_SUCCESS);
                SessionUtils.updateSession(taraSession);
                return "redirect:" + response.getBody().get("redirect_to").toString();
            } else {
                throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
            }
        }
    }

    @NotNull
    private HttpEntity<AcceptConsentRequest> createRequestBody(TaraSession taraSession) {
        AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();

        Map<String, Object> profileAttributes = new LinkedHashMap<>();

        addProfile_attributes(profileAttributes, taraSession);

        taraSession.getAllowedAuthMethods();

        acceptConsentRequest.setSession(new AcceptConsentRequest.LoginSession(
                profileAttributes
        ));

        profileAttributes.put("state", getStateParameterValue(taraSession));
        profileAttributes.put("amr", taraSession.getAuthenticationResult().getAmr());

        HttpEntity<AcceptConsentRequest> request = new HttpEntity<>(acceptConsentRequest);
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
        AcceptConsentRequest.LoginSession session;
        @JsonProperty("grant_scope")
        String[] grantScope = new String[]{"openid", "mid"};

        @Data
        @RequiredArgsConstructor
        public static class LoginSession {
            @JsonProperty("access_token")
            private Map accessToken;
            @JsonProperty("id_token")
            private final Map idToken;
        }
    }
}
