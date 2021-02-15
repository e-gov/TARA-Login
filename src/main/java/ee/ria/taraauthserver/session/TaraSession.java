package ee.ria.taraauthserver.session;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.error.ErrorCode;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.Assert;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.net.URL;
import java.time.LocalDate;
import java.util.*;

import static java.util.Arrays.stream;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static org.springframework.util.CollectionUtils.isEmpty;

@Slf4j
@Data
@RequiredArgsConstructor
public class TaraSession implements Serializable {
    public static final String TARA_SESSION = "tara.session";
    private final String sessionId;
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
        private ErrorCode errorCode;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @RequiredArgsConstructor
    public static class MidAuthenticationResult extends AuthenticationResult {
        private final String midSessionId;
    }

    @Slf4j
    @Data
    @EqualsAndHashCode(callSuper = true)
    @RequiredArgsConstructor
    public static class SidAuthenticationResult extends AuthenticationResult {
        private final String sidSessionId;
    }

    @Data
    public static class LoginRequestInfo implements Serializable {
        @JsonProperty("challenge")
        private String challenge;
        private boolean isLoginChallengeExpired = false;
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

        public List<AuthenticationType> getAllowedAuthenticationMethodsList(AuthConfigurationProperties taraProperties) {
            List<AuthenticationType> requestedAuthMethods = getRequestedAuthenticationMethodList(taraProperties);
            List<AuthenticationType> allowedAuthenticationMethodsList = requestedAuthMethods.stream()
                    .filter(method -> isAuthenticationMethodEnabled(method, taraProperties))
                    .filter(authMethod -> isAuthenticationMethodAllowedByRequestedLoa(authMethod, taraProperties))
                    .collect(toList());

            log.debug("List of authentication methods to display on login page: {}", allowedAuthenticationMethodsList);
            return allowedAuthenticationMethodsList;
        }

        private List<AuthenticationType> getRequestedAuthenticationMethodList(AuthConfigurationProperties taraProperties) {
            List<TaraScope> requestedTaraScopes = getRequestedTaraScopes();
            List<AuthenticationType> clientRequestedAuthMethods = stream(AuthenticationType.values())
                    .filter(authenticationType -> requestedTaraScopes.contains(authenticationType.getScope()))
                    .collect(toList());

            if (isEmpty(clientRequestedAuthMethods)) {
                return taraProperties.getDefaultAuthenticationMethods();
            } else {
                return clientRequestedAuthMethods;
            }
        }

        private List<TaraScope> getRequestedTaraScopes() {
            List<TaraScope> allowedRequestedScopes = new ArrayList<>();
            List<String> allowedScopes = of(client.getScope().split(" "));
            for (String requestedScope : requestedScopes) {
                if (allowedScopes.contains(requestedScope)) {
                    TaraScope taraScope = TaraScope.getScope(requestedScope);
                    if (taraScope != null) {
                        allowedRequestedScopes.add(taraScope);
                    } else {
                        log.warn("Unsupported scope value '{}', entry ignored!", requestedScope);
                    }
                } else {
                    log.warn("Requested scope value '{}' is not allowed, entry ignored!", requestedScope);
                }
            }
            return allowedRequestedScopes;
        }

        private boolean isAuthenticationMethodAllowedByRequestedLoa(AuthenticationType autMethod, AuthConfigurationProperties taraProperties) {
            LevelOfAssurance requestedLoa = getRequestedAcr();
            if (requestedLoa == null)
                return true;
            return isAllowedByRequestedLoa(requestedLoa, autMethod, taraProperties);
        }

        private LevelOfAssurance getRequestedAcr() {
            List<String> requestedAcr = getOidcContext().getAcrValues();
            if (requestedAcr == null || requestedAcr.isEmpty())
                return null;
            LevelOfAssurance acr = LevelOfAssurance.findByAcrName(requestedAcr.get(0));
            Assert.notNull(acr, "Unsupported acr value requested by client: '" + requestedAcr.get(0) + "'");
            return acr;
        }

        private boolean isAllowedByRequestedLoa(LevelOfAssurance requestedLoa, AuthenticationType authenticationMethod, AuthConfigurationProperties taraProperties) {
            LevelOfAssurance authenticationMethodLoa = taraProperties.getAuthMethods().get(authenticationMethod).getLevelOfAssurance();
            boolean isAllowed = authenticationMethodLoa.ordinal() >= requestedLoa.ordinal();

            if (!isAllowed) {
                log.warn("Ignoring authentication method since it's level of assurance is lower than requested. Authentication method: {} with assigned LoA: {}, requested level of assurance: {}",
                        authenticationMethod, authenticationMethodLoa, requestedLoa);
            }
            return isAllowed;
        }

        private boolean isAuthenticationMethodEnabled(AuthenticationType method, AuthConfigurationProperties taraProperties) {
            return taraProperties.getAuthMethods().get(method).isEnabled();
        }
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
        private boolean displayUserConsent;
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
        @JsonProperty("smartid_settings")
        private SmartIdSettings smartIdSettings;
    }

    @Data
    public static class SmartIdSettings implements Serializable {
        @JsonProperty("relying_party_UUID")
        private String relyingPartyUuid;
        @JsonProperty("relying_party_name")
        private String relyingPartyName;
        @JsonProperty("should_use_additional_verifcation_code_check")
        private Boolean ShouldUseAdditionalVerificationCodeCheck;
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

    public String getOidcClientTranslatedShortName() {
        OidcClient oidcClient = getLoginRequestInfo().getClient().getMetaData().getOidcClient();
        String translatedShortName = oidcClient.getShortName();

        if (oidcClient.getNameTranslations() != null) {
            Map<String, String> serviceNameTranslations = oidcClient.getNameTranslations();
            Locale locale = LocaleContextHolder.getLocale();
            if (serviceNameTranslations.containsKey(locale.getLanguage()))
                translatedShortName = serviceNameTranslations.get(locale.getLanguage());
        }
        return translatedShortName;
    }
}
