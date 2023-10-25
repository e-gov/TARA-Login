package ee.ria.taraauthserver.authentication.veriff;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.EnumSet;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_VERIFF;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_VERIFF_STATUS;
import static java.util.Map.of;

@Slf4j
@RestController
public class VeriffPollController {
    private static final EnumSet<TaraAuthenticationState> ALLOWED_STATES = EnumSet.of(INIT_VERIFF, POLL_VERIFF_STATUS, VERIFICATION_FAILED, VERIFICATION_COMPLETED);

    @GetMapping(value = "/auth/veriff/poll")
    public Map<String, String> authVeriffPoll() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);

        if (taraSession.getState() == VERIFICATION_COMPLETED) {
            return of("status", "COMPLETED");
        } else if (taraSession.getState() == VERIFICATION_FAILED) {
            ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
            String[] reason = taraSession.getAuthenticationResult().getReason();
            if (errorCode.equals(ErrorCode.ERROR_GENERAL))
                throw new IllegalStateException(errorCode.getMessage());
            else if (errorCode.equals(ErrorCode.VERIFF_INTERNAL_ERROR))
                throw new ServiceNotAvailableException(errorCode, "Veriff poll failed", null);
            else
                throw new BadRequestException(errorCode, "Veriff poll failed", reason);
        } else
            return of("status", "PENDING");
    }
}