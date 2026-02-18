package ee.ria.taraauthserver.authentication.common;

import org.springframework.context.MessageSource;
import org.springframework.stereotype.Component;
import org.springframework.context.i18n.LocaleContextHolder;

@Component
public class AuthenticationDisplayTextBuilder {

    private static final String LOGIN_DISPLAY_TEXT_KEY =
            "message.authentication.display-text";

    private final MessageSource messageSource;

    public AuthenticationDisplayTextBuilder(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    public String buildLoginDisplayText(String shortName) {
        if (shortName == null) {
            return null;
        }

        return messageSource.getMessage(
                LOGIN_DISPLAY_TEXT_KEY,
                new Object[]{shortName},
                LocaleContextHolder.getLocale()
        );
    }
}
