package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.FlowType;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_WEB2APP;

@Value
public class InitSmartIdWeb2AppAuthenticationSessionUpdate implements TaraSessionUpdate {

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, INIT_AUTH_PROCESS);
        session.setSmartIdFlowType(FlowType.WEB2APP);
        session.setState(INIT_SID_WEB2APP);
        session.setSmartIdWeb2AppSession(null);
    }
}
