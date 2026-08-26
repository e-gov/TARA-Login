package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Value;

import java.util.Set;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_CALLBACK;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_DC_API_RESPONSE;

@Value
public class CancelEudiAuthenticationSessionUpdate implements TaraSessionUpdate {

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, Set.of(WAITING_EUDI_CALLBACK, WAITING_EUDI_DC_API_RESPONSE));

        session.setEudiSession(null);
        session.setState(AUTHENTICATION_CANCELED);
    }

}
