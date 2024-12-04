package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import jakarta.validation.constraints.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;


import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Validated
@Controller
public class AuthRejectController {

    @Autowired
    private StatisticsLogger statisticsLogger;

    @Autowired
    private HydraService hydraService;

    @GetMapping("/auth/reject")
    public RedirectView authReject(@RequestParam(name = "error_code") @Pattern(regexp = "user_cancel", message = "the only supported value is: 'user_cancel'") String errorCode,
                                   @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        }

        RedirectView redirectView = new RedirectView(hydraService.rejectLogin(errorCode, taraSession));
        taraSession.setState(AUTHENTICATION_CANCELED);
        statisticsLogger.log(taraSession);
        SessionUtils.invalidateSession();
        return redirectView;
    }
}
