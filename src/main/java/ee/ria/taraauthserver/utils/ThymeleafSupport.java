package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;

import java.util.List;
import java.util.Locale;
import java.util.Map;

@Slf4j
public class ThymeleafSupport {

    public boolean isNotLocale(String code, Locale locale) {
        return !locale.getLanguage().equalsIgnoreCase(code);
    }

    public String getHomeUrl() {
        TaraSession taraSession = SessionUtils.getOrCreateAuthSession();
        if (taraSession.getLoginRequestInfo() == null)
            return "#";

        TaraSession.OidcClient oidcClient = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient();
        if (oidcClient.getLegacyReturnUrl() != null)
            return oidcClient.getLegacyReturnUrl();
        else
            return "/auth/reject?error_code=user_cancel";
    }

    public String getBackUrl() {
        TaraSession taraSession = SessionUtils.getOrCreateAuthSession();
        if (taraSession.getLoginRequestInfo() != null)
            return "/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge();
        else
            return "#";
    }

    public String getServiceName() {
        TaraSession taraSession = SessionUtils.getOrCreateAuthSession();
        if (taraSession.getLoginRequestInfo() == null)
            return null;

        String defaultServicename = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getName();
        if (defaultServicename == null)
            return null;

        Map<String, String> serviceNameTranslations = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations();
        Locale locale = LocaleContextHolder.getLocale();
        if (serviceNameTranslations.containsKey(locale.getLanguage()))
            return serviceNameTranslations.get(locale.getLanguage());
        else
            return defaultServicename;
    }

    public String getLocaleUrl(String locale) { // TODO test this part
        UriComponents uriComponents = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("lang", locale).build();
        return uriComponents.getPath() + "?" + uriComponents.getQuery();
    }

    public boolean isAuthMethodAllowed(AuthenticationType method) {
        Assert.notNull(method, "Authentication method can not be null!");

        List<AuthenticationType> clientSpecificAuthMethodList = SessionUtils.getOrCreateAuthSession().getAllowedAuthMethods();
        if (clientSpecificAuthMethodList == null || clientSpecificAuthMethodList.size() == 0) {
            return false;
        }

        return clientSpecificAuthMethodList.contains(method);
    }

}