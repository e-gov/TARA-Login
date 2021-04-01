package ee.ria.taraauthserver.session;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.error.ErrorCode;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
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

    private TaraAuthenticationState state;
    private LoginRequestInfo loginRequestInfo;
    private List<AuthenticationType> allowedAuthMethods;
    private AuthenticationResult authenticationResult;
    private List<LegalPerson> legalPersonList;
    private LegalPerson selectedLegalPerson;
    private String consentChallenge;

    public void setState(TaraAuthenticationState newState) {
        log.info(append("tara.session.session_id", this.sessionId), "Tara session state change: {} -> {}",
                value("tara.session.old_state", state != null ? state.name() : "NOT_SET"),
                value("tara.session.state", newState.name()));
        this.state = newState;
    }

    public String getClientName() {
        return Optional.of(this)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getNameTranslations)
                .map(m -> m.get("et"))
                .orElse(null);
    }

    public boolean isEmailScopeRequested() {
        return getLoginRequestInfo().getRequestedScopes().contains(TaraScope.EMAIL.getFormalName());
    }

    public boolean isPhoneNumberScopeRequested() {
        return getLoginRequestInfo().getRequestedScopes().contains(TaraScope.PHONE.getFormalName());
    }

    @Data
    public static class AuthenticationResult implements Serializable {
        private String email;
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

        public String getOidcState() {
            return URLEncodedUtils.parse(url.getQuery(), UTF_8)
                    .stream()
                    .filter(p -> p.getName().equals("state"))
                    .map(NameValuePair::getValue)
                    .findFirst()
                    .orElse("not set");
        }

        public List<AuthenticationType> getAllowedAuthenticationMethodsList(AuthConfigurationProperties taraProperties) {
            if (requestedScopes.contains("eidasonly"))
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
                if (allowedScopes.contains(requestedScope)) {
                    TaraScope taraScope = TaraScope.getScope(requestedScope);
                    if (taraScope != null) {
                        allowedRequestedScopes.add(taraScope);
                    } else {
                        log.warn("Unsupported scope value '{}', entry ignored!",
                                value("tara.session.login_request_info.requested_scope", requestedScope));
                    }
                } else {
                    log.warn("Requested scope value '{}' is not allowed, entry ignored!",
                            value("tara.session.login_request_info.requested_scope", requestedScope));
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
                log.warn(append("tara.session.login_request_info", this),
                        "Ignoring authentication method since it's level of assurance is lower than requested. Authentication method: {} with assigned LoA: {}, requested level of assurance: {}",
                        value("tara.session.login_request_info.authentication_method", authenticationMethod),
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
        @Valid
        @JsonProperty("institution")
        private Institution institution = new Institution();
        @JsonProperty("smartid_settings")
        private SmartIdSettings smartIdSettings;
        @JsonProperty("mid_settings")
        private MidSettings midSettings;
    }

    @Data
    public static class SmartIdSettings implements Serializable {
        @JsonProperty("relying_party_UUID")
        private String relyingPartyUuid;
        @JsonProperty("relying_party_name")
        private String relyingPartyName;
        @JsonProperty("should_use_additional_verification_code_check")
        private Boolean shouldUseAdditionalVerificationCodeCheck;
    }

    @Data
    public static class MidSettings implements Serializable {
        @JsonProperty("relying_party_UUID")
        private String relyingPartyUuid;
        @JsonProperty("relying_party_name")
        private String relyingPartyName;
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
        String translatedShortName = oidcClient.getShortNameTranslations().get("et");

        Map<String, String> shortNameTranslations = oidcClient.getShortNameTranslations();
        Locale locale = LocaleContextHolder.getLocale();
        if (shortNameTranslations.containsKey(locale.getLanguage()))
            translatedShortName = shortNameTranslations.get(locale.getLanguage());

        return translatedShortName;
    }

    public Boolean isAdditionalSmartIdVerificationCodeCheckNeeded() {
        return Optional.of(this)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getSmartIdSettings)
                .map(TaraSession.SmartIdSettings::getShouldUseAdditionalVerificationCodeCheck)
                .orElse(true);
    }

    public Optional<String> getSmartIdRelyingPartyName() {
        return Optional.of(this)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getSmartIdSettings)
                .map(TaraSession.SmartIdSettings::getRelyingPartyName);
    }

    public Optional<String> getSmartIdRelyingPartyUuid() {
        return Optional.of(this)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getSmartIdSettings)
                .map(TaraSession.SmartIdSettings::getRelyingPartyUuid);
    }
}
