package ee.ria.taraauthserver.authentication.common;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthenticationDisplayTextFactoryTest {

    private static final String DEFAULT_DISPLAY_NAME = "Default display name";
    private MessageSource messageSource;
    private AuthenticationDisplayTextFactory factory;

    @BeforeEach
    void setUp() {
        messageSource = mock(MessageSource.class);
        factory = new AuthenticationDisplayTextFactory(messageSource, DEFAULT_DISPLAY_NAME);
    }

    @AfterEach
    void tearDown() {
        LocaleContextHolder.resetLocaleContext();
    }

    @ParameterizedTest
    @CsvSource({
            "et",
            "en",
            "ru"
    })
    void createLoginDisplayText_whenShortNameIsNull_formattedMessageWithDefaultServiceNameReturned(String languageTag) {
        String expected = "<login-display-text>";

        Locale locale = Locale.forLanguageTag(languageTag);
        LocaleContextHolder.setLocale(locale);

        when(messageSource.getMessage(
                AuthenticationDisplayTextFactory.LOGIN_DISPLAY_TEXT_KEY,
                new Object[]{DEFAULT_DISPLAY_NAME},
                locale))
                .thenReturn(expected);

        String result = factory.createLoginDisplayText(null);

        assertThat(result).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({
            "et, Logi sisse: Test Service",
            "en, Log in: Test Service",
            "ru, Войти: Test Service"
    })
    void createLoginDisplayText_whenServiceNameProvided_formattedMessageReturned(
            String languageTag, String expected) {
        Locale locale = Locale.forLanguageTag(languageTag);
        LocaleContextHolder.setLocale(locale);

        when(messageSource.getMessage(
                AuthenticationDisplayTextFactory.LOGIN_DISPLAY_TEXT_KEY,
                new Object[]{"Test Service"},
                locale))
                .thenReturn(expected);

        String result = factory.createLoginDisplayText("Test Service");

        assertEquals(expected, result);
    }
}
