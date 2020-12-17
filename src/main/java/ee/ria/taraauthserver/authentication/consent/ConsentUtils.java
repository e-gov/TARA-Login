package ee.ria.taraauthserver.authentication.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.experimental.UtilityClass;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpEntity;
import org.springframework.util.Assert;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.List.of;

@UtilityClass
public class ConsentUtils {

    @NotNull
    public HttpEntity<AcceptConsentRequest> createRequestBody(TaraSession taraSession) {
        AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();
        AcceptConsentRequest.LoginSession loginSession = new AcceptConsentRequest.LoginSession();
        AcceptConsentRequest.IdToken idToken = new AcceptConsentRequest.IdToken();
        AcceptConsentRequest.ProfileAttributes profileAttributes = new AcceptConsentRequest.ProfileAttributes();

        profileAttributes.setGivenName(taraSession.getAuthenticationResult().getFirstName());
        profileAttributes.setFamilyName(taraSession.getAuthenticationResult().getLastName());
        profileAttributes.setDateOfBirth(taraSession.getAuthenticationResult().getDateOfBirth().toString());

        TaraSession.LegalPerson legalPerson = taraSession.getSelectedLegalPerson();
        if (legalPerson != null) {
            AcceptConsentRequest.RepresentsLegalPerson representsLegalPerson = new AcceptConsentRequest.RepresentsLegalPerson();
            representsLegalPerson.setName(legalPerson.getLegalName());
            representsLegalPerson.setRegistryCode(legalPerson.getLegalPersonIdentifier());
            profileAttributes.setRepresentsLegalPerson(representsLegalPerson);
        }

        idToken.setProfileAttributes(profileAttributes);
        idToken.setAcr(taraSession.getAuthenticationResult().getAcr().getAcrName());
        idToken.setAmr(of(taraSession.getAuthenticationResult().getAmr().getAmrName()));
        idToken.setState(getStateParameterValue(taraSession));
        loginSession.setIdToken(idToken);
        acceptConsentRequest.setSession(loginSession);

        List<String> requestedScopes = taraSession.getLoginRequestInfo().getRequestedScopes();
        List<String> allowedScopes = of(taraSession.getLoginRequestInfo().getClient().getScope().split(" "));

        List<String> scope = requestedScopes.stream()
                .distinct()
                .filter(allowedScopes::contains)
                .collect(Collectors.toList());
        scope.add("openid");

        acceptConsentRequest.setGrantScope(scope);
        return new HttpEntity<>(acceptConsentRequest);
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
        List<String> grantScope;

        @Data
        public static class LoginSession {
            @JsonProperty("id_token")
            private IdToken idToken;
        }

        @Data
        public static class IdToken {
            @JsonProperty("profile_attributes")
            private ProfileAttributes profileAttributes;
            @JsonProperty("acr")
            private String acr;
            @JsonProperty("amr")
            private List<String> amr;
            @JsonProperty("state")
            private String state;
        }

        @Data
        public static class ProfileAttributes {
            @JsonProperty("family_name")
            private String familyName;
            @JsonProperty("given_name")
            private String givenName;
            @JsonProperty("date_of_birth")
            private String dateOfBirth;
            @JsonProperty("represents_legal_person")
            private RepresentsLegalPerson representsLegalPerson;
        }

        @Data
        public static class RepresentsLegalPerson {
            @JsonProperty("name")
            private String name;
            @JsonProperty("registry_code")
            private String registryCode;
        }
    }

}
