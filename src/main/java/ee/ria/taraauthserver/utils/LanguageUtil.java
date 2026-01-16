package ee.ria.taraauthserver.utils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.util.Locale;
import java.util.MissingResourceException;

@Slf4j
@UtilityClass
public class LanguageUtil {

    private final String DEFAULT_LANG_ISO3 = "eng";

    public String toIso3(String iso2) {
        try {
            return new Locale(iso2).getISO3Language();
        } catch (MissingResourceException e) {
            log.error("Invalid ISO2 language ID: {}", iso2);
            return DEFAULT_LANG_ISO3;
        }
    }

    public String toIso3(Locale locale) {
        try {
            return locale.getISO3Language();
        } catch (MissingResourceException e) {
            log.error("Cannot produce 3-letter ISO language abbreviation for locale {}", locale);
            return DEFAULT_LANG_ISO3;
        }
    }
}
