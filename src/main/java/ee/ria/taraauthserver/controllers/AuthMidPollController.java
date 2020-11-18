package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.error.ErrorMessages;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
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


        AuthSession authSession = SessionUtils.getAuthSession();
        log.info("authSession in authMidPollController: " + authSession);
        if (authSession.getState() == AuthState.AUTHENTICATION_FAILED) {
            throw new BadRequestException(((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage(), "AuthSession state is: " + AuthState.AUTHENTICATION_FAILED);
        }
        if (authSession.getState() != AuthState.NATURAL_PERSON_AUTHENTICATION_COMPLETED && authSession.getState() != AuthState.POLL_MID_STATUS) {
            throw new BadRequestException(ErrorMessages.SESSION_STATE_INVALID, String.format("Session not in expected status. Expected one of: %s, but was %s", List.of(AuthState.NATURAL_PERSON_AUTHENTICATION_COMPLETED,AuthState.POLL_MID_STATUS), authSession.getState()));
        }
        Map<String, String> map = new HashMap<>();
        if (authSession.getState() == AuthState.NATURAL_PERSON_AUTHENTICATION_COMPLETED)
            map.put("status", "COMPLETED");
        else
            map.put("status", "PENDING");
        return map;
    }
}
