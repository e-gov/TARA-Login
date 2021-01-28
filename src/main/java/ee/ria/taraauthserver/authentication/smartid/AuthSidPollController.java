package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
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
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS;

@Slf4j
@RestController
public class AuthSidPollController {

    private static final TaraAuthenticationState[] ALLOWED_STATES = {POLL_SID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED};

    @GetMapping(value = "/auth/sid/poll")
    public ModelAndView authSidPoll() {
        TaraSession taraSession = SessionUtils.getAuthSession();
        SessionUtils.assertSessionInState(taraSession, ALLOWED_STATES);

        if (taraSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED) {
            return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "COMPLETED"));
        } else if (taraSession.getState() == AUTHENTICATION_FAILED)
            throw new BadRequestException(taraSession.getAuthenticationResult().getErrorCode(), "Mid poll failed");
        else
            return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "PENDING"));
    }

}
