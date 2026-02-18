package ee.ria.taraauthserver.authentication.common;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthenticationDisplayTextBuilderTest {

    private static final String PREFIX_KEY = "message.authentication.display-text";

    private final MessageSource messageSource = mock(MessageSource.class);
    private final AuthenticationDisplayTextBuilder builder = new AuthenticationDisplayTextBuilder(messageSource);

    @AfterEach
    void tearDown() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void buildLoginDisplayText_whenShortNameIsNull_returnsNull() {
        String result = builder.buildLoginDisplayText(null);
        assertNull(result);
    }

    @ParameterizedTest
    @CsvSource({
            "et, Logi sisse: Test Service",
            "en, Log in: Test Service",
            "ru, Войти: Test Service"
    })
    void buildLoginDisplayText_formatsMessage_forDifferentLocales(String languageTag, String expected) {
        Locale locale = Locale.forLanguageTag(languageTag);
        LocaleContextHolder.setLocale(locale);

        when(messageSource.getMessage(
                PREFIX_KEY,
                new Object[]{"Test Service"},
                locale))
                .thenReturn(expected);

        String result = builder.buildLoginDisplayText("Test Service");

        assertEquals(expected, result);
    }
}
