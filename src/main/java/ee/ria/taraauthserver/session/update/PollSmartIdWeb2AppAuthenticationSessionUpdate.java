package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;

@Value
public class PollSmartIdWeb2AppAuthenticationSessionUpdate implements TaraSessionUpdate {

    String sidSessionId;
    DeviceLinkAuthenticationSessionRequest authenticationSessionRequest;

    @Override
    public void apply(TaraSession session) {
        TaraSession.SmartIdWeb2AppSession smartIdWeb2AppSession = new TaraSession.SmartIdWeb2AppSession(
                sidSessionId,
                authenticationSessionRequest
        );
        session.setSmartIdWeb2AppSession(smartIdWeb2AppSession);
        session.setState(POLL_SID_WEB2APP_STATUS);
    }
}
