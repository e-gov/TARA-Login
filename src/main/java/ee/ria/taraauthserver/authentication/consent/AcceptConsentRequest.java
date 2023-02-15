package ee.ria.taraauthserver.authentication.consent;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Builder;
import lombok.Data;
import org.springframework.util.Assert;

import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.List.of;

@Data
public class AcceptConsentRequest {
    @JsonProperty("remember")
    private Boolean remember = false;
    @JsonProperty("session")
    private AcceptConsentRequest.LoginSession session;
    @JsonProperty("grant_scope")
    private List<String> grantScope;

    @Builder
    public static AcceptConsentRequest buildWithTaraSession(TaraSession taraSession) {
        AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();
        AcceptConsentRequest.LoginSession loginSession = new AcceptConsentRequest.LoginSession();
        AcceptConsentRequest.IdToken idToken = new AcceptConsentRequest.IdToken();
        AcceptConsentRequest.ProfileAttributes profileAttributes = new AcceptConsentRequest.ProfileAttributes();

        profileAttributes.setGivenName(taraSession.getAuthenticationResult().getFirstName());
        profileAttributes.setFamilyName(taraSession.getAuthenticationResult().getLastName());
        // profileAttributes.setDateOfBirth(taraSession.getAuthenticationResult().getDateOfBirth().toString());

        if (phoneNumberIsRequested(taraSession) && taraSession.getAuthenticationResult().getAmr().equals(AuthenticationType.MOBILE_ID)) {
            idToken.setPhoneNr(taraSession.getAuthenticationResult().getPhoneNumber());
            idToken.setPhoneNrVerified(true);
        }

        if (emailIsRequested(taraSession) && taraSession.getAuthenticationResult().getAmr().equals(AuthenticationType.ID_CARD)) {
            idToken.setEmail(taraSession.getAuthenticationResult().getEmail());
            idToken.setEmailVerified(false);
        }

        TaraSession.LegalPerson legalPerson = taraSession.getSelectedLegalPerson();
        if (legalPerson != null) {
            AcceptConsentRequest.RepresentsLegalPerson representsLegalPerson = new AcceptConsentRequest.RepresentsLegalPerson();
            representsLegalPerson.setName(legalPerson.getLegalName());
            representsLegalPerson.setRegistryCode(legalPerson.getLegalPersonIdentifier());
            profileAttributes.setRepresentsLegalPerson(representsLegalPerson);
        }

        idToken.setProfileAttributes(profileAttributes);
        idToken.setState(getStateParameterValue(taraSession));
        if (taraSession.getGovSsoLoginRequestInfo() != null)
            idToken.setGovSsoLoginChallenge(taraSession.getGovSsoLoginRequestInfo().getChallenge());
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
        return acceptConsentRequest;
    }

    private static boolean emailIsRequested(TaraSession taraSession) {
        return taraSession.getLoginRequestInfo().getRequestedScopes().contains(TaraScope.EMAIL.getFormalName());
    }

    private static boolean phoneNumberIsRequested(TaraSession taraSession) {
        return taraSession.getLoginRequestInfo().getRequestedScopes().contains(TaraScope.PHONE.getFormalName());
    }

    private static String getStateParameterValue(TaraSession taraSession) {
        URL oidcAuthRequestUrl = (taraSession).getLoginRequestInfo().getUrl();
        Assert.notNull(oidcAuthRequestUrl, "OIDC authentication URL cannot be null!");
        String state = getQueryMap(oidcAuthRequestUrl.getQuery()).get("state");
        Assert.notNull(state, "State paremeter is mandatory and cannot be null!");
        return URLDecoder.decode(state, StandardCharsets.UTF_8);
    }

    private static Map<String, String> getQueryMap(String query) {
        String[] params = query.split("&");
        Map<String, String> map = new HashMap<>();

        for (String param : params) {
            String[] nameValuePair = param.split("=", 2);
            if (nameValuePair.length > 1) {
                String name = nameValuePair[0];
                String value = nameValuePair[1];
                map.put(name, value);
            }
        }
        return map;
    }

    @Data
    public static class LoginSession {
        @JsonProperty("id_token")
        private AcceptConsentRequest.IdToken idToken;
    }

    @Data
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class IdToken {
        @JsonProperty("profile_attributes")
        private AcceptConsentRequest.ProfileAttributes profileAttributes;
        @JsonProperty("state")
        private String state;
        @JsonProperty("email")
        private String email;
        @JsonProperty("email_verified")
        private Boolean emailVerified;
        @JsonProperty("phone_number")
        private String phoneNr;
        @JsonProperty("phone_number_verified")
        private Boolean phoneNrVerified;
        @JsonProperty("govsso_login_challenge")
        private String govSsoLoginChallenge;
    }

    @Data
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ProfileAttributes {
        @JsonProperty("family_name")
        private String familyName;
        @JsonProperty("given_name")
        private String givenName;
        @JsonProperty("date_of_birth")
        private String dateOfBirth;
        @JsonProperty("represents_legal_person")
        private AcceptConsentRequest.RepresentsLegalPerson representsLegalPerson;
    }

    @Data
    public static class RepresentsLegalPerson {
        @JsonProperty("name")
        private String name;
        @JsonProperty("registry_code")
        private String registryCode;
    }
}
