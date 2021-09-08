package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.util.EnumSet;

import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.EnumSet.of;

@Slf4j
@RestController
public class AuthMidPollCancelController {
    private static final EnumSet<TaraAuthenticationState> ALLOWED_STATES = of(INIT_MID, POLL_MID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED);

    @PostMapping(value = "/auth/mid/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView authMidPollCancel(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        } else if (taraSession.getState().equals(AUTHENTICATION_SUCCESS)) {
            String redirectUri = taraSession.getLoginRequestInfo().getRedirectUri();
            String encodedState = URLEncoder.encode(taraSession.getLoginRequestInfo().getOidcState(), UTF_8);
            return new RedirectView(redirectUri + "?error=user_cancel&error_description=User+canceled+the+authentication+process.&state=" + encodedState);
        } else if (!ALLOWED_STATES.contains(taraSession.getState())) {
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, format("Invalid authentication state: '%s', expected one of: %s", taraSession.getState(), ALLOWED_STATES));
        }

        taraSession.setState(POLL_MID_STATUS_CANCELED);
        log.warn("Mobile-ID authentication process has been canceled");
        return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge());
    }
}
