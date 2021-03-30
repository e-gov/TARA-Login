package ee.ria.taraauthserver.authentication.mobileid;

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
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@RestController
public class AuthMidPollController {
    private static final TaraAuthenticationState[] ALLOWED_STATES = {INIT_MID, POLL_MID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED};

    @GetMapping(value = "/auth/mid/poll")
    public Map<String, String> authMidPoll() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);

        String midSessionId = ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId();
        log.info(append("tara.session.state", taraSession.getState()),
                "Polling Mobile-ID authentication process with MID session id {}",
                value("tara.session.authentication_result.mid_session_id", midSessionId));

        if (taraSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED) {
            return of("status", "COMPLETED");
        } else if (taraSession.getState() == AUTHENTICATION_FAILED) {
            ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
            if (errorCode.equals(ErrorCode.ERROR_GENERAL))
                throw new IllegalStateException(errorCode.getMessage());
            else if (errorCode.equals(ErrorCode.MID_INTERNAL_ERROR))
                throw new ServiceNotAvailableException(errorCode, "Mobile-ID poll failed", null);
            else
                throw new BadRequestException(taraSession.getAuthenticationResult().getErrorCode(), "Mobile-ID poll failed");
        } else
            return of("status", "PENDING");
    }
}