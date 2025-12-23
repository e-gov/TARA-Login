package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_QR_CODE;

@Value
public class InitSmartIdQrCodeAuthenticationSessionUpdate implements TaraSessionUpdate {

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, INIT_AUTH_PROCESS);

        TaraSession.SidAuthenticationResult authenticationResult =
                new TaraSession.SidAuthenticationResult(null);
        authenticationResult.setAmr(AuthenticationType.SMART_ID);
        session.setAuthenticationResult(authenticationResult);

        session.setState(INIT_SID_QR_CODE);
    }

}
