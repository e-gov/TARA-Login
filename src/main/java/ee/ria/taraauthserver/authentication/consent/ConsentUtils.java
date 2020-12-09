package ee.ria.taraauthserver.authentication.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.UtilityClass;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpEntity;
import org.springframework.util.Assert;

import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@UtilityClass
public class ConsentUtils {

    @NotNull
    public HttpEntity<AcceptConsentRequest> createRequestBody(TaraSession taraSession) {
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
