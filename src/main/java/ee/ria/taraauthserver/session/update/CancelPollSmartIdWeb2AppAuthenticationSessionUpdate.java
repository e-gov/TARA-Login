package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Value;

import java.util.EnumSet;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_WEB2APP;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_STATUS_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED;

@Value
public class CancelPollSmartIdWeb2AppAuthenticationSessionUpdate implements TaraSessionUpdate {

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, EnumSet.of(
                INIT_SID_WEB2APP,
                POLL_SID_WEB2APP_STATUS,
                POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED,
                AUTHENTICATION_FAILED,
                NATURAL_PERSON_AUTHENTICATION_COMPLETED,
                LEGAL_PERSON_AUTHENTICATION_COMPLETED
        ));
        session.setState(POLL_SID_STATUS_CANCELED);
    }

}
