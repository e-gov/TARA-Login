package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.SmartIdWeb2AppSession.SmartIdWeb2AppCallbackParameters;
import lombok.Value;

import java.util.Set;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;

@Value
public class CallbackSmartIdWeb2AppAuthenticationSessionUpdate implements TaraSessionUpdate {

    String value;
    String sessionSecretDigest;
    String userChallengeVerifier;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, Set.of(
                POLL_SID_WEB2APP_STATUS,
                NATURAL_PERSON_AUTHENTICATION_COMPLETED,
                AUTHENTICATION_FAILED
        ));
        session.getSmartIdWeb2AppSession().setCallbackParameters(new SmartIdWeb2AppCallbackParameters(
                value,
                sessionSecretDigest,
                userChallengeVerifier
        ));
    }
}
