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
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;

@Slf4j
@RestController
public class AuthMidPollController {
    private static final TaraAuthenticationState[] ALLOWED_STATES = {INIT_MID, POLL_MID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED};

    @GetMapping(value = "/auth/mid/poll")
    public ModelAndView authMidPoll() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);
        if (log.isDebugEnabled()) {
            log.debug("Polling for response from Mobile ID authentication process with MID session id {}",
                    ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId());
        }

        if (taraSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED) {
            return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "COMPLETED"));
        } else if (taraSession.getState() == AUTHENTICATION_FAILED) {
            ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
            if (errorCode.equals(ErrorCode.ERROR_GENERAL))
                throw new IllegalStateException(errorCode.getMessage());
            else if (errorCode.equals(ErrorCode.MID_INTERNAL_ERROR))
                throw new ServiceNotAvailableException(errorCode, "Sid poll failed", null);
            else
                throw new BadRequestException(taraSession.getAuthenticationResult().getErrorCode(), "Sid poll failed");
        } else
            return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "PENDING"));
    }
}