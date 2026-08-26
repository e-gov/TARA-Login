package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.EudiFlow;
import lombok.NonNull;
import lombok.Value;

import java.time.Instant;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_DC_API_RESPONSE;

@Value
public class InitEudiDcApiAuthenticationSessionUpdate implements TaraSessionUpdate {

    @NonNull String presentationSessionId;
    @NonNull String walletNonce;
    @NonNull Instant authFlowStartTime;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, INIT_AUTH_PROCESS);

        session.setEudiSession(new TaraSession.EudiSession(presentationSessionId, walletNonce));
        session.setEudiFlowType(EudiFlow.DC_API);
        session.setAuthFlowStartTime(authFlowStartTime);

        TaraSession.EudiAuthenticationResult authenticationResult = new TaraSession.EudiAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.EUDI_WALLET);
        session.setAuthenticationResult(authenticationResult);

        session.setState(WAITING_EUDI_DC_API_RESPONSE);
    }

}
