package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import lombok.NonNull;
import lombok.Value;

import java.time.Instant;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_QR_CODE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_QR_CODE;

@Value
public class PollSmartIdQrCodeAuthenticationSessionUpdate implements TaraSessionUpdate {

    @NonNull Instant startTime;
    @NonNull RpChallenge rpChallenge;
    @NonNull DeviceLinkAuthenticationSessionRequest initSmartIdSessionRequest;
    @NonNull DeviceLinkSessionResponse initSmartIdSessionResponse;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, INIT_SID_QR_CODE);

        TaraSession.SmartIdQrCodeSession smartIdSession = new TaraSession.SmartIdQrCodeSession(
                startTime,
                rpChallenge,
                initSmartIdSessionRequest.relyingPartyName(),
                initSmartIdSessionRequest.interactions(),
                initSmartIdSessionResponse.deviceLinkBase().toString(),
                initSmartIdSessionResponse.sessionToken(),
                initSmartIdSessionResponse.sessionSecret()
        );
        session.setSmartIdQrCodeSession(smartIdSession);
        session.setState(POLL_SID_QR_CODE);
    }

}
