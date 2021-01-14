package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@RestController
public class AuthMidPollController {
    private static final TaraAuthenticationState[] ALLOWED_STATES = {INIT_MID, POLL_MID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED};

    @GetMapping(value = "/auth/mid/poll")
    @ResponseBody
    public ModelAndView authMidPoll(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);
        log.debug("Polling for response from Mobile ID authentication process with MID session id {}",
                ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId());

        if (taraSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED) {
            SessionUtils.resetHttpSession(taraSession);
            return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "COMPLETED"));
        } else if (taraSession.getState() == AUTHENTICATION_FAILED)
            throw new BadRequestException(taraSession.getAuthenticationResult().getErrorCode(), "Mid poll failed");
        else
            return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "PENDING"));
    }
}
