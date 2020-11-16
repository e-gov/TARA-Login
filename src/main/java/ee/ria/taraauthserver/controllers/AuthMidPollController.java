package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.util.HashMap;

@Slf4j
@RestController
public class AuthMidPollController {

    @GetMapping(value = "/auth/mid/poll", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public HashMap<String, String> authMidPoll(HttpSession httpSession) {

        AuthSession authSession = (AuthSession) httpSession.getAttribute("session");
        log.info("authSession in authMidPollController: " + authSession);
        if (authSession == null) {
            log.error("AuthSession is null");
            throw new BadRequestException("Bad request");
        }
        if (authSession.getState() == AuthState.AUTHENTICATION_FAILED) {
            log.error("AuthSession state is: " + AuthState.AUTHENTICATION_FAILED);
            throw new BadRequestException(((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
        }
        if (authSession.getState() != AuthState.AUTHENTICATION_SUCCESS && authSession.getState() != AuthState.POLL_MID_STATUS) {
            log.error("AuthSession state is incorrect");
            throw new BadRequestException("Bad request");
        }
        HashMap<String, String> map = new HashMap<>();
        if (authSession.getState() == AuthState.AUTHENTICATION_SUCCESS)
            map.put("status", "COMPLETED");
        else
            map.put("status", "PENDING");
        return map;
    }
}
