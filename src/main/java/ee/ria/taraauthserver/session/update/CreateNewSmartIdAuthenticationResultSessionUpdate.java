package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Value;

import java.util.Set;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_WEB2APP;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;

@Value
public class CreateNewSmartIdAuthenticationResultSessionUpdate implements TaraSessionUpdate {

    String sidSessionId;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, Set.of(INIT_SID_WEB2APP, POLL_SID_WEB2APP_STATUS));
        TaraSession.SidAuthenticationResult sidAuthenticationResult = new TaraSession.SidAuthenticationResult(sidSessionId);
        sidAuthenticationResult.setAmr(AuthenticationType.SMART_ID);
        session.setAuthenticationResult(sidAuthenticationResult);
    }

}
