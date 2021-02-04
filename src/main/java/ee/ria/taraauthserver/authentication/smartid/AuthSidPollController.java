package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static java.util.Map.of;

@Slf4j
@RestController
public class AuthSidPollController {
    private static final TaraAuthenticationState[] ALLOWED_STATES = {INIT_SID, POLL_SID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED};

    @GetMapping(value = "/auth/sid/poll")
    public Map<String, String> authSidPoll() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);

        if (taraSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED) {
            return of("status", "COMPLETED");
        } else if (taraSession.getState() == AUTHENTICATION_FAILED) {
            ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
            if (errorCode.equals(ErrorCode.ERROR_GENERAL))
                throw new IllegalStateException(errorCode.getMessage());
            else if (errorCode.equals(ErrorCode.SID_INTERNAL_ERROR))
                throw new ServiceNotAvailableException(errorCode, "Sid poll failed", null);
            else
                throw new BadRequestException(taraSession.getAuthenticationResult().getErrorCode(), "Sid poll failed");
        } else
            return of("status", "PENDING");
    }

}
