package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.error.Exceptions.BadRequestException;
import ee.ria.taraauthserver.error.ErrorTranslationCodes;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.utils.SessionUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
public class AuthMidPollController {

    @GetMapping(value = "/auth/mid/poll", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, String> authMidPoll(HttpSession httpSession) {


        TaraSession taraSession = SessionUtils.getAuthSession();
        log.info("authSession in authMidPollController: " + taraSession);
        if (taraSession.getState() == TaraAuthenticationState.AUTHENTICATION_FAILED) {
            throw new BadRequestException(((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage(), "AuthSession state is: " + TaraAuthenticationState.AUTHENTICATION_FAILED);
        }
        if (taraSession.getState() != TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED && taraSession.getState() != TaraAuthenticationState.POLL_MID_STATUS) {
            throw new BadRequestException(ErrorTranslationCodes.SESSION_STATE_INVALID, String.format("Session not in expected status. Expected one of: %s, but was %s", List.of(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, TaraAuthenticationState.POLL_MID_STATUS), taraSession.getState()));
        }
        Map<String, String> map = new HashMap<>();
        if (taraSession.getState() == TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED)
            map.put("status", "COMPLETED");
        else
            map.put("status", "PENDING");
        return map;
    }
}
