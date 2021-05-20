package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.alerts.AlertsScheduler;
import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties.Alert;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;

@Slf4j
public class ThymeleafSupport {

    @Autowired(required = false)
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired(required = false)
    private AuthConfigurationProperties authConfigurationProperties;

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

        String defaultServicename = taraSession.getClientName();
        if (defaultServicename == null)
            return null;

        Map<String, String> serviceNameTranslations = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations();
        Locale locale = LocaleContextHolder.getLocale();
        return serviceNameTranslations.getOrDefault(locale.getLanguage(), defaultServicename);
    }

    public String getLocaleUrl(String locale) {
        UriComponents uriComponents = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("lang", locale).build();
        return uriComponents.getPath() + "?" + uriComponents.getQuery();
    }

    public Set<String> getListOfCountries() {
        return eidasConfigurationProperties == null ? emptySet() : eidasConfigurationProperties.getAvailableCountries();
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
        return alertsScheduler == null ? emptyList() : alertsScheduler.getActiveAlerts();
    }

    public String getErrorReportEmail() {
        return authConfigurationProperties.getErrorReportEmail();
    }
}