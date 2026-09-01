package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.FlowType;
import lombok.NonNull;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_QR_CODE;

@Value
public class InitSmartIdQrCodeAuthenticationSessionUpdate implements TaraSessionUpdate {

    @NonNull String pollingNodeId;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, INIT_AUTH_PROCESS);

        session.setSmartIdFlowType(FlowType.QR);
        session.setPollingNodeId(pollingNodeId);
        TaraSession.SidAuthenticationResult authenticationResult =
                new TaraSession.SidAuthenticationResult(null);
        authenticationResult.setAmr(AuthenticationType.SMART_ID);
        session.setAuthenticationResult(authenticationResult);

        session.setState(INIT_SID_QR_CODE);
    }

}
