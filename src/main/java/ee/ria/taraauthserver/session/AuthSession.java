package ee.ria.taraauthserver.session;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.AuthenticationType;
import ee.ria.taraauthserver.config.LevelOfAssurance;
import lombok.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.net.URL;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@ToString
@NoArgsConstructor
public class AuthSession implements Serializable {
    private AuthState state;
    private LoginRequestInfo loginRequestInfo;
    private List<AuthenticationType> allowedAuthMethods;
    private AuthenticationResult authenticationResult;
    private List<LegalPerson> legalPersonList;
    private LegalPerson selectedLegalPerson;

    @Data
    @ToString
    public static class AuthenticationResult implements Serializable {
        private String idCode;
        private String country;
        private String firstName;
        private String lastName;
        private String phoneNumber;
        private String subject;
        private LocalDate dateOfBirth;
        private AuthenticationType amr;
        private LevelOfAssurance acr; //TODO acr vs LevelOfAssurance vs loa, choose one
    }

    @Data
    @ToString
    public static class MidAuthenticationResult extends AuthenticationResult {
        private String midSessionId;
        private String errorMessage;
        private int errorStatus;
    }

    @Data
    @ToString
    public static class LoginRequestInfo implements Serializable {
        @JsonProperty("challenge")
        String challenge;
        @Valid
        @JsonProperty("client")
        private Client client = new Client();
        @JsonProperty("requested_scope")
        List<String> requestedScopes = new ArrayList<>();
        @Valid
        @JsonProperty("oidc_context")
        OidcContext oidcContext = new OidcContext();
        @JsonProperty("request_url")
        URL url;
    }

    @Data
    @ToString
    public static class Client implements Serializable {
        @JsonProperty("client_id")
        @NotBlank
        @Size(max = 150)
        String clientId;
        @Valid
        @JsonProperty("metadata")
        MetaData metaData = new MetaData();
        @NotBlank
        @JsonProperty("scope")
        String scope;
    }

    @Data
    @ToString
    public static class OidcContext implements Serializable {
        @JsonProperty("acr_values")
        List<String> acrValues;
        @JsonProperty("ui_locales")
        List<String> uiLocales;
    }

    @Data
    @ToString
    public static class MetaData implements Serializable {
        @Valid
        @JsonProperty("oidc_client")
        OidcClient oidcClient = new OidcClient();
    }

    @Data
    @ToString
    public static class OidcClient implements Serializable {
        @NotBlank
        @Size(max = 150)
        @JsonProperty("name")
        String name;
        @JsonProperty("name_translations")
        Map<String, String> nameTranslations = new HashMap<>();
        @NotBlank
        @Size(max = 40)
        @JsonProperty("short_name")
        String shortName;
        @JsonProperty("short_name_translations")
        Map<String, String> shortNameTranslations = new HashMap<>();
        @Size(max = 1000)
        @JsonProperty("legacy_return_url")
        String legacyReturnUrl;
        @Valid
        @JsonProperty("institution")
        Institution institution = new Institution();
    }

    @Data
    @ToString
    public static class Institution implements Serializable {
        @NotBlank
        @Pattern(regexp = "(private|public)", message = "invalid sector value, accepted values are: private, public")
        @JsonProperty("sector")
        String sector;
    }

    @ToString
    @EqualsAndHashCode
    @RequiredArgsConstructor
    @Getter
    public static class LegalPerson implements Serializable {
        private final String legalName;
        private final String legalPersonIdentifier;
    }
}
