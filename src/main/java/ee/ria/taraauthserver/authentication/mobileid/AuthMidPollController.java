package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.SessionUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
public class AuthMidPollController {

    @GetMapping(value = "/auth/mid/poll", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, String> authMidPoll() {

        TaraSession taraSession = SessionUtils.getAuthSession();
        log.info("Polling for response from Mobile ID authentication process with MID session id {}",
                ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId());

        List<TaraAuthenticationState> allowedStates =
                List.of(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, TaraAuthenticationState.POLL_MID_STATUS);
        SessionUtils.assertSessionNotInState(taraSession, TaraAuthenticationState.AUTHENTICATION_FAILED);
        SessionUtils.assertSessionInState(taraSession, allowedStates);

        if (taraSession.getState() == TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED)
            return Map.of("status", "COMPLETED");
        else
            return Map.of("status", "PENDING");
    }
}
