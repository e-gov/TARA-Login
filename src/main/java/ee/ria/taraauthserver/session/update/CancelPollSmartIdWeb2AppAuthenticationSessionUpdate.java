package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Value;

import java.util.EnumSet;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS_CANCELED;

@Value
public class CancelPollSmartIdWeb2AppAuthenticationSessionUpdate implements TaraSessionUpdate {

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, EnumSet.of(
                POLL_SID_WEB2APP_STATUS,
                AUTHENTICATION_FAILED,
                NATURAL_PERSON_AUTHENTICATION_COMPLETED,
                LEGAL_PERSON_AUTHENTICATION_COMPLETED
        ));
        session.setState(POLL_SID_WEB2APP_STATUS_CANCELED);
    }

}
