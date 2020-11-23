package ee.ria.taraauthserver.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpSession;
import java.net.URL;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static ee.ria.taraauthserver.config.properties.Constants.TARA_SESSION;

@Validated
@RestController
@Slf4j
public class MockAuthController {

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

    @PostMapping(value = "/mockauth", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView mockAuth(HttpSession session) {
        TaraSession taraSession = (TaraSession) session.getAttribute(TARA_SESSION);
        log.info("current state: " + taraSession.getState());
        log.info("session id in AUTH_MOCK: " + session.getId());
        TaraSession.AuthenticationResult authResult = new TaraSession.AuthenticationResult();
        authResult.setAcr(LevelOfAssurance.HIGH);
        authResult.setSubject("EE60001019906");
        authResult.setFirstName("Firstname");
        authResult.setLastName("Lastname");
        authResult.setDateOfBirth(LocalDate.now());
        taraSession.setAuthenticationResult(authResult);
        taraSession.setState(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        session.setAttribute(TARA_SESSION, taraSession);
        log.info("edited session " + session.getAttribute(TARA_SESSION));
        log.info("with id " + session.getId());
        return new RedirectView("/auth/accept");
    }

    @GetMapping(value = "/heartbeat", produces = MediaType.TEXT_HTML_VALUE)
    public String heartbeat() {
        return "it just works";
    }

    @GetMapping("/auth/id")
    public String mockAuthId() {
        return "{\"ok\":true}";
    }

    // TODO invalidate session
    @GetMapping(value = "/consent", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> mockConsent(@RequestParam String consent_challenge, HttpSession session) {
        TaraSession taraSession = (TaraSession) session.getAttribute(TARA_SESSION);

        String url = authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + consent_challenge;
        AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();
        HttpEntity<AcceptConsentRequest> request = new HttpEntity<>(acceptConsentRequest);

        Map<String, Object> profileAttributes =new LinkedHashMap<>();

        addProfile_attributes(profileAttributes, taraSession);

        acceptConsentRequest.setSession(new AcceptConsentRequest.LoginSession(
                profileAttributes
        ));

        profileAttributes.put("state", getStateParameterValue(taraSession));
        profileAttributes.put("amr", new String[]{"mid"});

        ResponseEntity<Map> response = hydraService.exchange(url, HttpMethod.PUT, request, Map.class);

        HttpHeaders headers = new HttpHeaders();
        headers.add("location", response.getBody().get("redirect_to").toString());
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    private void addLegalPersonAttributes(Map<String, Object> attributes, TaraSession.LegalPerson legalPerson) {
        Map<String, Object> legalPersonAttributes = Map.of(
                "name", legalPerson.getLegalName(),
                "registry_code", legalPerson.getLegalPersonIdentifier()
        );
        attributes.put("represents_legal_person", legalPersonAttributes);
    }

    @NotNull
    private void addProfile_attributes(Map<String, Object> attributes, TaraSession taraSession) {
        Map<String, Object> profileAttributes = new LinkedHashMap<>();
        profileAttributes.put("family_name", taraSession.getAuthenticationResult().getLastName());
        profileAttributes.put("given_name", taraSession.getAuthenticationResult().getFirstName());
        profileAttributes.put("date_of_birth", taraSession.getAuthenticationResult().getDateOfBirth().toString());
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
        Boolean remember = false;

        @JsonProperty("session")
        LoginSession session;

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
