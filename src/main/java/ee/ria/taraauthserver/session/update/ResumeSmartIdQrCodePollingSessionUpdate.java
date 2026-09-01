package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.NonNull;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_QR_CODE;

@Value
public class ResumeSmartIdQrCodePollingSessionUpdate implements TaraSessionUpdate {

    @NonNull String pollingNodeId;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, POLL_SID_QR_CODE);

        session.setPollingNodeId(pollingNodeId);
    }

}
