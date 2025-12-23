package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.session.TaraSession;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

import static java.util.regex.Pattern.compile;

@Slf4j
@UtilityClass
public class RequestUtils {

    public final Predicate<String> SUPPORTED_LANGUAGES = compile("(?i)(et|en|ru)").asMatchPredicate();
    public static final String LANG_PARAM_NAME = "lang";

    public static void setLocale(String requestedLocale) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
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

    public static String getLangParam(TaraSession taraSession) {
        String langParamValue = getLangParamValue(taraSession);
        return langParamValue != null ? "&" + LANG_PARAM_NAME + "=" + langParamValue : "";
    }

    public static @Nullable String getLangParamValue(@Nullable TaraSession taraSession) {
        if (taraSession == null) {
            return null;
        }
        String chosenLanguage = taraSession.getChosenLanguage();
        if (chosenLanguage == null) {
            return null;
        }
        if (!SUPPORTED_LANGUAGES.test(chosenLanguage)) {
            log.warn("Chosen language \"{}\" not supported", chosenLanguage);
            return null;
        }
        return chosenLanguage;
    }

    public static <T> Consumer<T> withMdc(Consumer<T> consumer) {
        Context context = mdc();
        return (t) -> {
            try {
                context.populate();
                consumer.accept(t);
            } finally {
                context.reset();
            }
        };
    }

    public static <T> Supplier<T> withMdc(Supplier<T> supplier) {
        Context context = mdc();
        return () -> {
            try {
                context.populate();
                return supplier.get();
            } finally {
                context.reset();
            }
        };
    }

    public static <T> Supplier<T> withMdcAndLocale(Supplier<T> supplier) {
        Context context = mdc().and(locale());
        return () -> {
            try {
                context.populate();
                return supplier.get();
            } finally {
                context.reset();
            }
        };
    }

    public static Runnable withMdcAndLocale(Runnable runnable) {
        Context context = mdc().and(locale());
        return () -> {
            try {
                context.populate();
                runnable.run();
            } finally {
                context.reset();
            }
        };
    }

    public static <T, R> Function<T, R> withMdcAndLocale(Function<T, R> function) {
        Context context = mdc().and(locale());
        return (input) -> {
            try {
                context.populate();
                return function.apply(input);
            } finally {
                context.reset();
            }
        };
    }

    private static Context mdc() {
        Map<String, String> mdc = MDC.getCopyOfContextMap();
        return new Context() {
            @Override
            public void populate() {
                if (mdc != null) {
                    MDC.setContextMap(mdc);
                } else {
                    MDC.clear();
                }
            }

            @Override
            public void reset() {
                MDC.clear();
            }
        };
    }

    private static Context locale() {
        Locale locale = LocaleContextHolder.getLocale();
        return new Context() {
            @Override
            public void populate() {
                LocaleContextHolder.setLocale(locale);
            }

            @Override
            public void reset() {
                LocaleContextHolder.setLocale(null);
            }
        };
    }

    private interface Context {

        void populate();

        void reset();

        default Context and(Context other) {
            Context self = this;
            return new Context() {
                @Override
                public void populate() {
                    self.populate();
                    other.populate();
                }

                @Override
                public void reset() {
                    self.reset();
                    other.reset();
                }
            };
        }

    }

}
