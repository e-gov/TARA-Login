package ee.ria.taraauthserver.authentication.consent;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpEntity;
import org.springframework.util.Assert;

import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.List.of;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
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
        log.info("accepting consent from: {}", value("tara.session.accept_consent_request", acceptConsentRequest));
        return new HttpEntity<>(acceptConsentRequest);
    }

    private String getStateParameterValue(TaraSession taraSession) {
        URL oidcAuthRequestUrl = (taraSession).getLoginRequestInfo().getUrl();
        Assert.notNull(oidcAuthRequestUrl, "OIDC authentication URL cannot be null!");
        String state = getQueryMap(oidcAuthRequestUrl.getQuery()).get("state");
        Assert.notNull(state, "State paremeter is mandatory and cannot be null!");
        return URLDecoder.decode(state, StandardCharsets.UTF_8);
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

    public boolean emailIsRequested(TaraSession taraSession) {
        return taraSession.getLoginRequestInfo().getRequestedScopes().contains(TaraScope.EMAIL.getFormalName());
    }

    public boolean phoneNumberIsRequested(TaraSession taraSession) {
        return taraSession.getLoginRequestInfo().getRequestedScopes().contains(TaraScope.PHONE.getFormalName());
    }

    @Data
    public static class AcceptConsentRequest {
        @JsonProperty("remember")
        private Boolean remember = false;
        @JsonProperty("session")
        private LoginSession session;
        @JsonProperty("grant_scope")
        private List<String> grantScope;

        @Data
        public static class LoginSession {
            @JsonProperty("id_token")
            private IdToken idToken;
        }

        @Data
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class IdToken {
            @JsonProperty("profile_attributes")
            private ProfileAttributes profileAttributes;
            @JsonProperty("acr")
            private String acr;
            @JsonProperty("amr")
            private List<String> amr;
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
