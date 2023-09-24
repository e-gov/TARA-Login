package ee.ria.taraauthserver.config.thymeleaf;

import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Locale;

@RequiredArgsConstructor
public class PrettyDatesExpression {

    private static final String DATETIME_FORMAT_KEY = "format.datetime";

    private static final String DATE_TEXT_FORMAT_KEY = "format.date.text";

    private static final String DATE_FORMAT_KEY = "format.date";

    private final MessageSource messageSource;

    public String dateTime(TemporalAccessor dateTime) {
        return getFormatter(DATETIME_FORMAT_KEY).format(dateTime);
    }

    public String dateText(TemporalAccessor dateText) {
        return getFormatter(DATE_TEXT_FORMAT_KEY).format(dateText);
    }

    public String date(TemporalAccessor date) {
        return getFormatter(DATE_FORMAT_KEY).format(date);
    }

    public DateTimeFormatter getFormatter(String code) {
        Locale locale = LocaleContextHolder.getLocale();
        String format = messageSource.getMessage(code, null, locale);
        return DateTimeFormatter.ofPattern(format, locale);
    }

}
