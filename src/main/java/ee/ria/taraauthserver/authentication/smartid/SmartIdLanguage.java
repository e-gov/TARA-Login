package ee.ria.taraauthserver.authentication.smartid;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Locale;

@Getter
@RequiredArgsConstructor
public enum SmartIdLanguage {

    EST("est"),
    ENG("eng"),
    RUS("rus");

    private final String value;

    public static SmartIdLanguage fromLocale(Locale locale) {
        return switch (locale.getLanguage()) {
            case "et" -> EST;
            case "en" -> ENG;
            case "ru" -> RUS;
            default -> null;
        };
    }

}
