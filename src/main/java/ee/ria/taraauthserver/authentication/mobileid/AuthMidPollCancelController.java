package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.SessionUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS_CANCELED;

@Slf4j
@RestController
public class AuthMidPollCancelController {

    @PostMapping(value = "/auth/mid/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public RedirectView authMidPollCancel() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        SessionUtils.assertSessionInState(taraSession, POLL_MID_STATUS);
        taraSession.setState(POLL_MID_STATUS_CANCELED);
        SessionUtils.updateSession(taraSession);
        log.warn("Mobile ID authentication process has been canceled");
        return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge());
    }
}
