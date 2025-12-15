package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;

@Value
public class FailSmartIdWeb2AppAuthenticationSessionUpdate implements TaraSessionUpdate {

    ErrorCode errorCode;

    @Override
    public void apply(TaraSession session) {
        session.setState(AUTHENTICATION_FAILED);
        session.getAuthenticationResult().setErrorCode(errorCode);
    }
}
