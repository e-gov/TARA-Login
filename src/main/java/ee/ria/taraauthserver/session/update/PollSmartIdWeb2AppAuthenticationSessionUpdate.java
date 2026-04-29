package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import lombok.NonNull;
import lombok.Value;

import java.time.Instant;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;

@Value
public class PollSmartIdWeb2AppAuthenticationSessionUpdate implements TaraSessionUpdate {

    String sidSessionId;
    String sessionSecret;
    String sessionToken;
    DeviceLinkAuthenticationSessionRequest authenticationSessionRequest;
    String urlToken;
    @NonNull Instant authFlowStartTime;

    @Override
    public void apply(TaraSession session) {
        TaraSession.SmartIdWeb2AppSession smartIdWeb2AppSession = new TaraSession.SmartIdWeb2AppSession(
                sidSessionId,
                sessionSecret,
                sessionToken,
                authenticationSessionRequest,
                urlToken
        );
        session.setSmartIdWeb2AppSession(smartIdWeb2AppSession);
        session.setAuthFlowStartTime(authFlowStartTime);
        session.setState(POLL_SID_WEB2APP_STATUS);
    }
}
