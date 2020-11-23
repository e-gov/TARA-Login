package ee.ria.taraauthserver.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Locale;

@Slf4j
public class RequestUtils {

    public static void setLocale(String requestedLocale) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();

        log.info("requested locale is: " + requestedLocale);
        Locale locale = StringUtils.parseLocaleString(requestedLocale);
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        Assert.notNull(localeResolver, "No LocaleResolver found in request: not in a DispatcherServlet request?");
        localeResolver.setLocale(request, response, locale);
    }

    public static Locale getLocale() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        return localeResolver.resolveLocale(request);
    }
}
