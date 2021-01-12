package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@RestController
public class AuthMidPollCancelController {
    private static final TaraAuthenticationState[] ALLOWED_STATES = {INIT_MID, POLL_MID_STATUS};

    @PostMapping(value = "/auth/mid/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public RedirectView authMidPollCancel(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);
        taraSession.setState(POLL_MID_STATUS_CANCELED);
        log.warn("Mobile ID authentication process with MID session id {} has been canceled",
                ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId());
        return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge());
    }
}
