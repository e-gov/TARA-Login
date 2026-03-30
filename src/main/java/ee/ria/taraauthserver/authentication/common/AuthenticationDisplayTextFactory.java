package ee.ria.taraauthserver.authentication.common;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

@RequiredArgsConstructor
public class AuthenticationDisplayTextFactory {

    static final String LOGIN_DISPLAY_TEXT_KEY =
            "message.authentication.display-text";

    private final MessageSource messageSource;
    private final String defaultDisplayName;

    public @NonNull String createLoginDisplayText(String clientDisplayName) {
        String displayName = defaultIfNull(
                clientDisplayName,
                defaultDisplayName);

        return messageSource.getMessage(
                LOGIN_DISPLAY_TEXT_KEY,
                new Object[]{displayName},
                LocaleContextHolder.getLocale()
        );
    }
}
