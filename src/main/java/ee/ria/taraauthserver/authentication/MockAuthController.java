package ee.ria.taraauthserver.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Validated
@RestController
@Slf4j
public class MockAuthController {

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate hydraService;

    private void addLegalPersonAttributes(Map<String, Object> attributes, TaraSession.LegalPerson legalPerson) {
        Map<String, Object> legalPersonAttributes = Map.of(
                "name", legalPerson.getLegalName(),
                "registry_code", legalPerson.getLegalPersonIdentifier()
        );
        attributes.put("legal_person", legalPersonAttributes);
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
