package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.NonNull;
import lombok.Value;

import java.util.List;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NOT_SET;

@Value
public class InitAuthSessionUpdate implements TaraSessionUpdate {

    private final @NonNull TaraSession.LoginRequestInfo loginRequestInfo;
    private final TaraSession.LoginRequestInfo govSsoLoginRequestInfo;
    private final @NonNull List<AuthenticationType> allowedAuthMethods;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, NOT_SET);

        session.setState(INIT_AUTH_PROCESS);
        session.setLoginRequestInfo(loginRequestInfo);
        session.setGovSsoLoginRequestInfo(govSsoLoginRequestInfo);
        session.setAllowedAuthMethods(allowedAuthMethods);
    }

}
