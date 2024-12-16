package ee.ria.taraauthserver.utils;

import static java.util.regex.Pattern.compile;

import ee.ria.taraauthserver.session.TaraSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.function.Predicate;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

@Slf4j
@UtilityClass
public class RequestUtils {

    public final Predicate<String> SUPPORTED_LANGUAGES = compile("(?i)(et|en|ru)").asMatchPredicate();

    public void setLocale(String requestedLocale) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
        Locale locale = StringUtils.parseLocaleString(requestedLocale);
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        Assert.notNull(localeResolver, "No LocaleResolver found in request: not in a DispatcherServlet request?");
        localeResolver.setLocale(request, response, locale);
    }

    public Locale getLocale() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        return localeResolver.resolveLocale(request);
    }

    public String getLangParam(TaraSession taraSession) {
        return (taraSession != null
            && taraSession.getChosenLanguage() != null
            && SUPPORTED_LANGUAGES.test(taraSession.getChosenLanguage()))
            ? "&lang=" + taraSession.getChosenLanguage()
            : "";
    }

    public static <T> Consumer<T> withMdc(Consumer<T> consumer) {
        Map<String, String> mdc = MDC.getCopyOfContextMap();
        return (t) -> {
            try {
                if (mdc != null) {
                    MDC.setContextMap(mdc);
                } else {
                    MDC.clear();
                }
                consumer.accept(t);
            } finally {
                MDC.clear();
            }
        };
    }

    public static <T> Supplier<T> withMdc(Supplier<T> supplier) {
        Map<String, String> mdc = MDC.getCopyOfContextMap();
        return () -> {
            try {
                if (mdc != null) {
                    MDC.setContextMap(mdc);
                } else {
                    MDC.clear();
                }
                return supplier.get();
            } finally {
                MDC.clear();
            }
        };
    }

    public static <T> Supplier<T> withMdcAndLocale(Supplier<T> supplier) {
        Map<String, String> mdc = MDC.getCopyOfContextMap();
        Locale locale = LocaleContextHolder.getLocale();
        return () -> {
            try {
                LocaleContextHolder.setLocale(locale);
                if (mdc != null) {
                    MDC.setContextMap(mdc);
                } else {
                    MDC.clear();
                }
                return supplier.get();
            } finally {
                MDC.clear();
                LocaleContextHolder.setLocale(null);
            }
        };
    }
}
