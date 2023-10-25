package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.alerts.AlertsScheduler;
import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties.Alert;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import org.json.JSONObject;

import java.time.OffsetDateTime;
import java.util.stream.Collectors;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Collections;

import static java.util.Collections.emptyMap;
import static java.util.Collections.emptyList;

@Slf4j
public class ThymeleafSupport {

    @Autowired(required = false)
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired(required = false)
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private AlertsConfigurationProperties alertsConfigurationProperties;

    @Autowired(required = false)
    private AlertsScheduler alertsScheduler;

    public boolean isNotLocale(String code, Locale locale) {
        return !locale.getLanguage().equalsIgnoreCase(code);
    }

    public String getHomeUrl() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        if (taraSession == null || taraSession.getLoginRequestInfo() == null)
            return "#";

        TaraSession.OidcClient oidcClient = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient();
        if (oidcClient.getLegacyReturnUrl() != null)
            return oidcClient.getLegacyReturnUrl();
        else
            return "/auth/reject?error_code=user_cancel";
    }

    public String getServiceName() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        if (taraSession == null || taraSession.getLoginRequestInfo() == null)
            return null;

        return taraSession.getOidcClientTranslatedName();
    }

    public String getServiceLogo() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        if (taraSession == null || taraSession.getLoginRequestInfo() == null)
            return null;

        TaraSession.LoginRequestInfo loginRequestInfo = taraSession.getAppropriateLoginRequestInfo();
        return loginRequestInfo.getClientLogo();
    }

    public String getLocaleUrl(String locale) {
        UriComponents uriComponents = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("lang", locale).build();
        return uriComponents.getPath() + "?" + uriComponents.getQuery();
    }

    public List<String> getListOfCountries( Map<String, List<String>> countries_with_methods) {
        if (countries_with_methods == null)
            return emptyList();

        return new ArrayList<>(countries_with_methods.keySet());
    }

    public Map<String, List<String>> getHashOfCountriesWithMethods() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        Map<SPType, Map<String, List<String>>> availableCountries = eidasConfigurationProperties.getAvailableCountries();
        if (eidasConfigurationProperties == null || taraSession == null || availableCountries == null)
            return emptyMap();
        List<String> allowedAuthMethods = toPropertyNames(taraSession.getAllowedAuthMethods());
        SPType spType = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getInstitution().getSector();
        List<String> methodsToCheck = new ArrayList<>(List.of("id-card", "smart-id", "mobile-id"));
        if (availableCountries.containsKey(spType)) {
            for (String country : availableCountries.get(spType).keySet()) {
                availableCountries.get(spType).get(country).removeIf(m -> !allowedAuthMethods.contains(m) && methodsToCheck.contains(m));
                if (availableCountries.get(spType).get(country).isEmpty()) 
                        availableCountries.get(spType).remove(country);
            }
        }
        return availableCountries.get(spType);
    }

    private List<String> toPropertyNames(List<AuthenticationType> allowedAuthMethods) {
        if (allowedAuthMethods.isEmpty())
            return emptyList();

        return allowedAuthMethods.stream()
            .map(AuthenticationType::getPropertyName)
            .collect(Collectors.toList());
    }

    public JSONObject toJSON(Map<String, List<String>> methods) {
        if (methods == null) {
            return new JSONObject();
        }
        return new JSONObject(methods);
    }

    public String getBackUrl() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        if (taraSession == null || taraSession.getLoginRequestInfo() == null || taraSession.getLoginRequestInfo().isLoginChallengeExpired())
            return "#";
        else
            return "/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge();
    }

    public boolean isAuthMethodAllowed(AuthenticationType method) {
        Assert.notNull(method, "Authentication method can not be null!");

        TaraSession taraSession = SessionUtils.getAuthSession();
        if (taraSession == null) {
            return false;
        }
        List<AuthenticationType> clientSpecificAuthMethodList = taraSession.getAllowedAuthMethods();
        if (clientSpecificAuthMethodList == null || clientSpecificAuthMethodList.isEmpty()) {
            return false;
        }

        return clientSpecificAuthMethodList.contains(method);
    }

    public List<Alert> getActiveAlerts() {
        List<Alert> alerts = new ArrayList<>();
        getStaticAlert().ifPresent(alerts::add);

        if (alertsScheduler != null)
            alerts.addAll(alertsScheduler.getActiveAlerts());
        return alerts;
    }

    public boolean hasStaticAlert() {
        return getStaticAlert().isPresent();
    }

    public String getErrorReportEmail() {
        return authConfigurationProperties.getErrorReportEmail();
    }

    private Optional<Alert> getStaticAlert() {
        AlertsConfigurationProperties.StaticAlert staticAlert = alertsConfigurationProperties.getStaticAlert();
        if (staticAlert == null) {
            return Optional.empty();
        }
        AlertsConfigurationProperties.LoginAlert loginAlert = AlertsConfigurationProperties.LoginAlert.builder()
                .enabled(true)
                .authMethods(AuthenticationType.getFormalNames())
                .messageTemplates(staticAlert.getMessageTemplates())
                .build();
        Alert alert = Alert.builder()
                .startTime(OffsetDateTime.now())
                .endTime(OffsetDateTime.now().plusYears(1))
                .build();
        alert.setLoginAlert(loginAlert);
        alert.setLoadedFromConf(true);
        return Optional.of(alert);
    }
}
