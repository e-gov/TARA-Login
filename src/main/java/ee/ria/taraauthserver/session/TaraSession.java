package ee.ria.taraauthserver.session;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.ErrorTranslationCodes;
import lombok.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
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
public class TaraSession implements Serializable {

    public static final String TARA_SESSION = "tara.session";

    private TaraAuthenticationState state;
    private LoginRequestInfo loginRequestInfo;
    private List<AuthenticationType> allowedAuthMethods;
    private AuthenticationResult authenticationResult;
    private List<LegalPerson> legalPersonList;
    private LegalPerson selectedLegalPerson;
    private String consentChallenge;

    @Data
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
    @EqualsAndHashCode(callSuper = true)
    public static class MidAuthenticationResult extends AuthenticationResult {
        private String midSessionId;
        private ErrorTranslationCodes errorMessage;
    }

    @Data
    public static class LoginRequestInfo implements Serializable {
        @JsonProperty("challenge")
        private String challenge;
        @Valid
        @JsonProperty("client")
        private Client client = new Client();
        @JsonProperty("requested_scope")
        private List<String> requestedScopes = new ArrayList<>();
        @Valid
        @JsonProperty("oidc_context")
        private OidcContext oidcContext = new OidcContext();
        @JsonProperty("request_url")
        private URL url;
    }

    @Data
    public static class Client implements Serializable {
        @JsonProperty("client_id")
        @NotBlank
        @Size(max = 150)
        private String clientId;
        @Valid
        @JsonProperty("metadata")
        private MetaData metaData = new MetaData();
        @NotBlank
        @JsonProperty("scope")
        private String scope;
    }

    @Data
    public static class OidcContext implements Serializable {
        @JsonProperty("acr_values")
        private List<String> acrValues;
        @JsonProperty("ui_locales")
        private List<String> uiLocales;
    }

    @Data
    public static class MetaData implements Serializable {
        @Valid
        @JsonProperty("oidc_client")
        private OidcClient oidcClient = new OidcClient();
        @NotNull
        @JsonProperty("display_user_consent")
        boolean display_user_consent;
    }

    @Data
    public static class OidcClient implements Serializable {
        @NotBlank
        @Size(max = 150)
        @JsonProperty("name")
        private String name;
        @JsonProperty("name_translations")
        private Map<String, String> nameTranslations = new HashMap<>();
        @NotBlank
        @Size(max = 40)
        @JsonProperty("short_name")
        private String shortName;
        @JsonProperty("short_name_translations")
        private Map<String, String> shortNameTranslations = new HashMap<>();
        @Size(max = 1000)
        @JsonProperty("legacy_return_url")
        private String legacyReturnUrl;
        @Valid
        @JsonProperty("institution")
        private Institution institution = new Institution();
    }

    @Data
    public static class Institution implements Serializable {
        @NotBlank
        @Pattern(regexp = "(private|public)", message = "invalid sector value, accepted values are: private, public")
        @JsonProperty("sector")
        private String sector;
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
