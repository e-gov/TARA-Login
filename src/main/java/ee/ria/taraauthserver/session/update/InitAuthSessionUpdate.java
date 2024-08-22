package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.NonNull;
import lombok.Value;

import java.util.List;

import static ee.ria.taraauthserver.session.SessionUtils.assertSessionInState;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;

@Value
public class InitAuthSessionUpdate implements TaraSessionUpdate {

    private final @NonNull TaraSession.LoginRequestInfo loginRequestInfo;
    private final TaraSession.LoginRequestInfo govSsoLoginRequestInfo;
    private final @NonNull List<AuthenticationType> allowedAuthMethods;

    @Override
    public void apply(TaraSession session) {
        assertSessionInState(session, NOT_SET);

        session.setState(INIT_AUTH_PROCESS);
        session.setLoginRequestInfo(loginRequestInfo);
        session.setGovSsoLoginRequestInfo(govSsoLoginRequestInfo);
        session.setAllowedAuthMethods(allowedAuthMethods);
    }

}
