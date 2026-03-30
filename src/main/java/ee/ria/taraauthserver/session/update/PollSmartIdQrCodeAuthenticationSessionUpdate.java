package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.authentication.smartid.SmartIdDeviceLinkSession;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.NonNull;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_QR_CODE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_QR_CODE;

@Value
public class PollSmartIdQrCodeAuthenticationSessionUpdate implements TaraSessionUpdate {

    @NonNull SmartIdDeviceLinkSession smartIdDeviceLinkSession;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, INIT_SID_QR_CODE);

        session.setSmartIdQrCodeSession(smartIdDeviceLinkSession);

        TaraSession.SidAuthenticationResult authenticationResult =
                new TaraSession.SidAuthenticationResult(smartIdDeviceLinkSession.sessionId());
        authenticationResult.setAmr(AuthenticationType.SMART_ID);
        session.setAuthenticationResult(authenticationResult);

        session.setState(POLL_SID_QR_CODE);
    }

}
