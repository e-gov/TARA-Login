package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.NonNull;
import lombok.Value;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EIDAS_RESPONSE;

@Value
public class InitEidasSessionUpdate implements TaraSessionUpdate {

    private final @NonNull TaraSession.EidasAuthenticationResult authenticationResult;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, INIT_AUTH_PROCESS);

        session.setState(WAITING_EIDAS_RESPONSE);
        session.setAuthenticationResult(authenticationResult);
    }

}
