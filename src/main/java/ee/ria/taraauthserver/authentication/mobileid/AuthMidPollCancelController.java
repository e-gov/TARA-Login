package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.InternalResourceView;
import org.springframework.web.servlet.view.RedirectView;

import java.util.EnumSet;

import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.EnumSet.of;

@Slf4j
@RestController
public class AuthMidPollCancelController {
    private static final EnumSet<TaraAuthenticationState> CANCELLABLE_STATES = of(INIT_MID, POLL_MID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED);

    @PostMapping(value = "/auth/mid/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    public View authMidPollCancel(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        } else {
            boolean isCancellableState = CANCELLABLE_STATES.contains(taraSession.getState());
            log.warn("Mobile-ID authentication process has been canceled");
            taraSession.setState(POLL_MID_STATUS_CANCELED);
            if (isCancellableState) {
                return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge());
            } else {
                return new InternalResourceView("/auth/reject?error_code=user_cancel");
            }
        }
    }
}
