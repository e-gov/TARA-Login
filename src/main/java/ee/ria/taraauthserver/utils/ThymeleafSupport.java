package ee.ria.taraauthserver.utils;

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

import java.util.*;

@Slf4j
public class ThymeleafSupport {

    @Autowired
    EidasConfigurationProperties eidasConfigurationProperties;

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

        String defaultServicename = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getName();
        if (defaultServicename == null)
            return null;

        Map<String, String> serviceNameTranslations = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations();
        Locale locale = LocaleContextHolder.getLocale();
        return serviceNameTranslations.getOrDefault(locale.getLanguage(), defaultServicename);
    }

    public String getLocaleUrl(String locale) { // TODO test this part
        UriComponents uriComponents = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("lang", locale).build();
        return uriComponents.getPath() + "?" + uriComponents.getQuery();
    }

    public List<String> getListOfCountries() {
        List<String> countries = eidasConfigurationProperties.getAvailableCountries();
        return countries;
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

}