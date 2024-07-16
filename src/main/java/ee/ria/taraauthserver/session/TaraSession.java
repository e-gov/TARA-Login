package ee.ria.taraauthserver.session;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.authentication.RelyingParty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.error.ErrorCode;
import eu.webeid.security.challenge.ChallengeNonce;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.util.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.Assert;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ee.ria.taraauthserver.config.properties.TaraScope.EMAIL;
import static ee.ria.taraauthserver.config.properties.TaraScope.PHONE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.stream;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static net.logstash.logback.argument.StructuredArguments.array;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.springframework.util.CollectionUtils.isEmpty;

@Slf4j
@Data
@RequiredArgsConstructor
public class TaraSession implements Serializable {
    public static final String TARA_SESSION = "tara.session";
    private final String sessionId;

    // NOTE: All field getters that should not be logged, must be annotated with @JsonIgnore
    private TaraAuthenticationState state;
    private LoginRequestInfo loginRequestInfo;
    private LoginRequestInfo govSsoLoginRequestInfo;
    private List<AuthenticationType> allowedAuthMethods;
    private AuthenticationResult authenticationResult;
    private List<LegalPerson> legalPersonList;
    private LegalPerson selectedLegalPerson;
    private String consentChallenge;
    private ChallengeNonce webEidChallengeNonce;

    public void setState(TaraAuthenticationState newState) {
        if (state == null || !state.equals(newState)) {
            log.info("State: {} -> {}",
                    value("tara.session.old_state", state != null ? state.name() : "NOT_SET"),
                    value("tara.session.state", newState.name()));
        }
        this.state = newState;
    }

    @JsonIgnore
    public boolean isEmailScopeRequested() {
        return isScopeRequested(EMAIL);
    }

    @JsonIgnore
    public boolean isPhoneNumberScopeRequested() {
        return isScopeRequested(PHONE);
    }

    public boolean isScopeRequested(TaraScope scope) {
        return Optional.of(this)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getRequestedScopes)
                .filter(scopes -> scopes.contains(scope.getFormalName()))
                .stream().findFirst().isPresent();
    }

    @Data
    public static class AuthenticationResult implements Serializable {
        private String email;
        private String idCode;
        private String country = "EE";
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
    public static class IdCardAuthenticationResult extends AuthenticationResult {
        private String ocspUrl;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @RequiredArgsConstructor
    public static class MidAuthenticationResult extends AuthenticationResult {
        private final String midSessionId;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @RequiredArgsConstructor
    public static class SidAuthenticationResult extends AuthenticationResult {
        private final String sidSessionId;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @RequiredArgsConstructor
    public static class EidasAuthenticationResult extends AuthenticationResult {
        private String relayState;
    }

    @Data
    public static class LoginRequestInfo implements Serializable {

        @NotNull
        @JsonProperty("challenge")
        private String challenge;

        private boolean isLoginChallengeExpired = false;

        @Valid
        @NotNull
        @JsonProperty("client")
        private Client client = new Client();

        @NotNull
        @JsonProperty("requested_scope")
        private List<String> requestedScopes = new ArrayList<>();

        @Valid
        @JsonProperty("oidc_context")
        private OidcContext oidcContext = new OidcContext();

        @NotNull
        @JsonProperty("request_url")
        private URL url;

        @JsonIgnore
        private String loginVerifierRedirectUrl;

        @JsonProperty("requested_at") //TODO AUT-1576 Add @NotNull and remove unnecessary check in AuthInitController
        private OffsetDateTime requestedAt;

        @JsonIgnore
        public String getOidcState() {
            return URLEncodedUtils.parse(url.getQuery(), UTF_8)
                    .stream()
                    .filter(p -> p.getName().equals("state"))
                    .map(NameValuePair::getValue)
                    .findFirst()
                    .orElse("not set");
        }

        @JsonIgnore
        public String getGovSsoChallenge() {
            return URLEncodedUtils.parse(url.getQuery(), UTF_8)
                    .stream()
                    .filter(p -> p.getName().equals("govsso_login_challenge"))
                    .map(NameValuePair::getValue)
                    .findFirst()
                    .orElse(null);
        }

        @JsonIgnore
        public String getRedirectUri() {
            return URLEncodedUtils.parse(url.getQuery(), UTF_8)
                    .stream()
                    .filter(p -> p.getName().equals("redirect_uri"))
                    .map(NameValuePair::getValue)
                    .findFirst()
                    .orElse("not set");
        }

        @JsonIgnore
        public String getUserCancelUri() {
            String redirectUri = getRedirectUri();
            String encodedState = URLEncoder.encode(getOidcState(), UTF_8);
            return redirectUri + "?error=user_cancel&error_description=User+canceled+the+authentication+process.&state=" + encodedState;
        }

        @JsonIgnore
        public String getClientId() {
            return Optional.of(this)
                    .map(TaraSession.LoginRequestInfo::getClient)
                    .map(TaraSession.Client::getClientId)
                    .orElse(null);
        }

        @JsonIgnore
        public Optional<OidcClient> getOidcClient() {
            return Optional.of(this)
                    .map(LoginRequestInfo::getClient)
                    .map(Client::getMetaData)
                    .map(MetaData::getOidcClient);
        }

        @JsonIgnore
        public Optional<Institution> getInstitution() {
            return getOidcClient()
                    .map(TaraSession.OidcClient::getInstitution);
        }

        public List<AuthenticationType> getAllowedAuthenticationMethodsList(AuthConfigurationProperties taraProperties) {
            if (requestedScopes.contains(TaraScope.EIDASONLY.getFormalName()))
                return List.of(AuthenticationType.EIDAS);

            List<AuthenticationType> requestedAuthMethods = getRequestedAuthenticationMethodList(taraProperties);
            List<AuthenticationType> allowedAuthenticationMethodsList = requestedAuthMethods.stream()
                    .filter(method -> isAuthenticationMethodEnabled(method, taraProperties))
                    .filter(authMethod -> isAuthenticationMethodAllowedByRequestedLoa(authMethod, taraProperties))
                    .collect(toList());

            log.debug("List of authentication methods to display on login page: {}",
                    array("tara.session.login_request_info.requested_scope", allowedAuthenticationMethodsList));
            return allowedAuthenticationMethodsList;
        }

        private List<AuthenticationType> getRequestedAuthenticationMethodList(AuthConfigurationProperties taraProperties) {
            List<TaraScope> requestedTaraScopes = getRequestedTaraScopes();
            List<AuthenticationType> clientRequestedAuthMethods = stream(AuthenticationType.values())
                    .filter(authenticationType -> requestedTaraScopes.contains(authenticationType.getScope()))
                    .collect(toList());

            if (isEmpty(clientRequestedAuthMethods)) {
                return getAllowedDefaultAuthenticationTypes(taraProperties);
            } else {
                return clientRequestedAuthMethods;
            }
        }

        private List<AuthenticationType> getAllowedDefaultAuthenticationTypes(AuthConfigurationProperties taraProperties) {
            List<AuthenticationType> allowedAuthenticationTypes = new ArrayList<>();
            List<String> allowedScopes = of(client.getScope().split(" "));
            for (AuthenticationType authType : taraProperties.getDefaultAuthenticationMethods()) {
                if (allowedScopes.contains(authType.getScope().getFormalName())) {
                    allowedAuthenticationTypes.add(authType);
                } else {
                    log.warn("Requested scope value '{}' is not allowed, entry ignored!",
                            value("tara.session.login_request_info.requested_scope", authType.getScope().getFormalName()));
                }
            }
            return allowedAuthenticationTypes;
        }

        private List<TaraScope> getRequestedTaraScopes() {
            List<TaraScope> allowedRequestedScopes = new ArrayList<>();
            List<String> allowedScopes = of(client.getScope().split(" "));
            for (String requestedScope : requestedScopes) {
                if (!allowedScopes.contains(requestedScope)) {
                    log.warn("Requested scope value '{}' is not allowed, entry ignored!",
                            value("tara.session.login_request_info.requested_scope", requestedScope));
                    continue;
                }
                TaraScope taraScope = TaraScope.getScope(requestedScope);
                if (taraScope == null) {
                    log.warn("Unsupported scope value '{}', entry ignored!",
                            value("tara.session.login_request_info.requested_scope", requestedScope));
                    continue;
                }
                allowedRequestedScopes.add(taraScope);
            }
            return allowedRequestedScopes;
        }

        private boolean isAuthenticationMethodAllowedByRequestedLoa(AuthenticationType autMethod, AuthConfigurationProperties taraProperties) {
            if (autMethod == AuthenticationType.EIDAS)
                return true;

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

        private boolean isAllowedByRequestedLoa(LevelOfAssurance requestedLoa, AuthenticationType authenticationMethodType, AuthConfigurationProperties taraProperties) {
            LevelOfAssurance authenticationMethodLoa = taraProperties.getAuthMethods().get(authenticationMethodType).getLevelOfAssurance();
            if (authenticationMethodLoa == null)
                throw new IllegalStateException("Level of assurance must be configured for authentication method: " + authenticationMethodType.getPropertyName() + ". Please check the application configuration.");

            boolean isAllowed = authenticationMethodLoa.ordinal() >= requestedLoa.ordinal();

            if (!isAllowed) {
                log.warn(append("tara.session.login_request_info", this),
                        "Ignoring authentication method since it's level of assurance is lower than requested. Authentication method: {} with assigned LoA: {}, requested level of assurance: {}",
                        value("tara.session.login_request_info.authentication_method", authenticationMethodType),
                        value("tara.session.login_request_info.authentication_method_loa", authenticationMethodLoa),
                        value("tara.session.login_request_info.requested_loa", requestedLoa));
            }
            return isAllowed;
        }

        private boolean isAuthenticationMethodEnabled(AuthenticationType method, AuthConfigurationProperties taraProperties) {
            return taraProperties.getAuthMethods().get(method) != null && taraProperties.getAuthMethods().get(method).isEnabled();
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

        @JsonIgnore
        public String getTranslatedShortName() {
            OidcClient oidcClient = getMetaData().getOidcClient();
            return getTranslatedValue(oidcClient.getShortNameTranslations());
        }

        @JsonIgnore
        public String getTranslatedName() {
            OidcClient oidcClient = getMetaData().getOidcClient();
            Map<String, String> nameTranslations = oidcClient.getNameTranslations();
            return getTranslatedValue(nameTranslations);
        }

        @JsonIgnore
        public String getLogo() {
            return Optional.of(getMetaData())
                    .map(MetaData::getOidcClient)
                    .map(TaraSession.OidcClient::getLogo)
                    .orElse(null);
        }

        private String getTranslatedValue(Map<String, String> translations) {
            String language = LocaleContextHolder.getLocale().getLanguage();
            if (translations.containsKey(language)) {
                return translations.get(language);
            }
            return translations.get("et");
        }

    }

    @Data
    public static class OidcContext implements Serializable {
        @JsonProperty("acr_values")
        private List<String> acrValues;
        @JsonProperty("ui_locales")
        private List<String> uiLocales = new ArrayList<>();
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
        @JsonProperty("name_translations")
        private Map<String, String> nameTranslations = new HashMap<>();
        @JsonProperty("short_name_translations")
        private Map<String, String> shortNameTranslations = new HashMap<>();
        @Size(max = 1000)
        @JsonProperty("legacy_return_url")
        private String legacyReturnUrl;
        @JsonProperty("eidas_requester_id")
        private URI eidasRequesterId;
        @Valid
        @JsonProperty("institution")
        private Institution institution = new Institution();
        @JsonProperty("smartid_settings")
        private SmartIdSettings smartIdSettings;
        @JsonProperty("mid_settings")
        private MidSettings midSettings;
        @JsonProperty("logo")
        private String logo;

        @JsonGetter("logo")
        public String getLogoSummary() {
            if (StringUtils.isBlank(logo)) {
                return logo;
            }
            return String.format("[%d] chars", logo.length());
        }
    }

    @Data
    public static class SmartIdSettings implements Serializable {
        @JsonProperty("relying_party_UUID")
        private String relyingPartyUuid;
        @JsonProperty("relying_party_name")
        private String relyingPartyName;
        @JsonProperty("should_use_additional_verification_code_check")
        private Boolean shouldUseAdditionalVerificationCodeCheck;

        @JsonIgnore
        public Optional<RelyingParty> getRelyingParty() {
            return RelyingParty.of(relyingPartyName, relyingPartyUuid);
        }

    }

    @Data
    public static class MidSettings implements Serializable {
        @JsonProperty("relying_party_UUID")
        private String relyingPartyUuid;
        @JsonProperty("relying_party_name")
        private String relyingPartyName;

        @JsonIgnore
        public Optional<RelyingParty> getRelyingParty() {
            return RelyingParty.of(relyingPartyName, relyingPartyUuid);
        }
    }

    @Data
    public static class Institution implements Serializable {
        @NotBlank
        @JsonProperty("registry_code")
        private String registryCode;

        @NotNull
        @JsonProperty("sector")
        private SPType sector;
    }

    @ToString
    @EqualsAndHashCode
    @RequiredArgsConstructor
    @Getter
    public static class LegalPerson implements Serializable {
        private final String legalName;
        private final String legalPersonIdentifier;
    }

    @JsonIgnore
    public TaraSession.Client getOriginalClient() {
        LoginRequestInfo govSsoLoginRequestInfo = getGovSsoLoginRequestInfo();
        if (govSsoLoginRequestInfo != null) {
            return govSsoLoginRequestInfo.getClient();
        }
        LoginRequestInfo loginRequestInfo = getLoginRequestInfo();
        if (loginRequestInfo != null) {
            return loginRequestInfo.getClient();
        }
        return null;
    }

    @JsonIgnore
    public Boolean isAdditionalSmartIdVerificationCodeCheckNeeded() {
        return Optional.of(getOriginalClient())
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getSmartIdSettings)
                .map(TaraSession.SmartIdSettings::getShouldUseAdditionalVerificationCodeCheck)
                .orElse(true);
    }

    public Optional<RelyingParty> getSmartIdRelyingParty() {
        Optional<RelyingParty> govSsoClientRelyingParty =
                Optional.ofNullable(getGovSsoLoginRequestInfo())
                        .flatMap(LoginRequestInfo::getOidcClient)
                        .map(OidcClient::getSmartIdSettings)
                        .flatMap(SmartIdSettings::getRelyingParty);
        if (govSsoClientRelyingParty.isPresent()) {
            return govSsoClientRelyingParty;
        }
        return Optional.ofNullable(getLoginRequestInfo())
                .flatMap(LoginRequestInfo::getOidcClient)
                .map(OidcClient::getSmartIdSettings)
                .flatMap(SmartIdSettings::getRelyingParty);
    }

    public Optional<RelyingParty> getMobileIdRelyingParty() {
        Optional<RelyingParty> govSsoClientRelyingParty =
                Optional.ofNullable(getGovSsoLoginRequestInfo())
                        .flatMap(LoginRequestInfo::getOidcClient)
                        .map(OidcClient::getMidSettings)
                        .flatMap(MidSettings::getRelyingParty);
        if (govSsoClientRelyingParty.isPresent()) {
            return govSsoClientRelyingParty;
        }
        return Optional.ofNullable(getLoginRequestInfo())
                .flatMap(LoginRequestInfo::getOidcClient)
                .map(OidcClient::getMidSettings)
                .flatMap(MidSettings::getRelyingParty);
    }

}
