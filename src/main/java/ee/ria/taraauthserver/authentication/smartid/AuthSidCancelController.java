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

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@RestController
public class AuthSidCancelController {
    private static final TaraAuthenticationState[] ALLOWED_STATES = {INIT_SID, POLL_SID_STATUS};

    @PostMapping(value = "/auth/sid/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView authSidPollCancel(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);
        taraSession.setState(POLL_SID_STATUS_CANCELED);
        log.warn("Smart ID authentication process with SID session id {} has been canceled",
                ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId());
        return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge());
    }
}
