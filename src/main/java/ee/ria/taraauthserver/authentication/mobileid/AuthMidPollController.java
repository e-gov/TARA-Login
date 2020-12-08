package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;

@Slf4j
@RestController
public class AuthMidPollController {

    @GetMapping(value = "/auth/mid/poll")
    @ResponseBody
    public ModelAndView authMidPoll() {

        TaraSession taraSession = SessionUtils.getAuthSession();
        log.debug("Polling for response from Mobile ID authentication process with MID session id {}",
                ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId());

        List<TaraAuthenticationState> allowedStates =
                List.of(NATURAL_PERSON_AUTHENTICATION_COMPLETED, POLL_MID_STATUS, AUTHENTICATION_FAILED);
        SessionUtils.assertSessionInState(taraSession, allowedStates);

        if (taraSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED)
            return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "COMPLETED"));
        else if (taraSession.getState() == AUTHENTICATION_FAILED)
            throw new BadRequestException(((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage(), "Mid poll failed");
        else
            return new ModelAndView(new MappingJackson2JsonView(), Map.of("status", "PENDING"));
    }
}
