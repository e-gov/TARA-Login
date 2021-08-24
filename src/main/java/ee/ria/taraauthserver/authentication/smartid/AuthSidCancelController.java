package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import java.util.EnumSet;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.EnumSet.of;

@Slf4j
@RestController
public class AuthSidCancelController {
    static final EnumSet<TaraAuthenticationState> ALLOWED_STATES = of(INIT_SID, POLL_SID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED);

    @PostMapping(value = "/auth/sid/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView authSidPollCancel(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);
        taraSession.setState(POLL_SID_STATUS_CANCELED);
        log.warn("Smart ID authentication process has been canceled");
        return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge());
    }
}
