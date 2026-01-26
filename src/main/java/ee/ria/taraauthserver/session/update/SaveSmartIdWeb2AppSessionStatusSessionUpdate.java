package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.rest.dao.SessionStatus;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED;

@Value
public class SaveSmartIdWeb2AppSessionStatusSessionUpdate implements TaraSessionUpdate {

    SessionStatus sessionStatus;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, POLL_SID_WEB2APP_STATUS);
        session.getSmartIdWeb2AppSession().setSessionStatus(sessionStatus);
        session.setState(POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED);
    }
}
