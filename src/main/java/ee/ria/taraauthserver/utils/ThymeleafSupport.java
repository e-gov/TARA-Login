package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.config.AuthenticationType;
import ee.ria.taraauthserver.session.AuthSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.List;
import java.util.Locale;
import java.util.Map;

@Slf4j
public class ThymeleafSupport {

    public boolean isNotLocale(String code, Locale locale) {
        return !locale.getLanguage().equalsIgnoreCase(code);
    }

    public String getHomeUrl() {
        AuthSession authSession = SessionUtils.getOrCreateAuthSession();
        if (authSession.getLoginRequestInfo() == null)
            return "#";

        AuthSession.OidcClient oidcClient = authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient();
        if (oidcClient.getLegacyReturnUrl() != null)
            return oidcClient.getLegacyReturnUrl();
        else
            return "/auth/reject?error_code=user_cancel";
    }

    public String getBackUrl() {
        AuthSession authSession = SessionUtils.getOrCreateAuthSession();
        if (authSession.getLoginRequestInfo() != null)
            return "/auth/init?login_challenge=" + authSession.getLoginRequestInfo().getChallenge();
        else
            return "#";
    }

    public String getServiceName() {
        AuthSession authSession = SessionUtils.getOrCreateAuthSession();
        if (authSession.getLoginRequestInfo() == null)
            return null;

        String defaultServicename = authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getName();
        if (defaultServicename == null)
            return null;

        Map<String, String> serviceNameTranslations = authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations();
        Locale locale = LocaleContextHolder.getLocale();
        if (serviceNameTranslations.containsKey(locale.getLanguage()))
            return serviceNameTranslations.get(locale.getLanguage());
        else
            return defaultServicename;
    }

    public String getLocaleUrl(String locale) {
        return ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("lang", locale).toUriString();
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