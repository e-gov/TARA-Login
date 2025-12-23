package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static java.util.Objects.requireNonNull;

@Value
public class AuthenticationFailedSessionUpdate implements TaraSessionUpdate {

    private final ErrorCode errorCode;

    @Override
    public void apply(TaraSession session) {
        TaraSession.AuthenticationResult authenticationResult = requireNonNull(session.getAuthenticationResult());
        authenticationResult.setErrorCode(errorCode);
        session.setState(AUTHENTICATION_FAILED);
    }

}
