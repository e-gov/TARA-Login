package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.net.URI;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@Validated
@Controller
@ConditionalOnProperty(
        value = {
                "tara.auth-methods.smart-id.enabled",
                "tara.auth-methods.smart-id.web2app.enabled"
        },
        havingValue = "true"
)
public class SmartIdWeb2AppController {

    @Autowired
    private AuthSidWeb2AppService authSidWeb2AppService;

    @GetMapping(value = "/auth/sid/web2app/init", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<Object> authSidInit(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Initiating Smart-ID Web2App authentication session");
        validateSession(taraSession);
        URI deviceLink = authSidWeb2AppService.startSidAuthSession(taraSession);
        return ResponseEntity
                .status(HttpStatus.SEE_OTHER.value())
                .header(HttpHeaders.LOCATION, deviceLink.toString())
                .build();
    }

    public void validateSession(TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.SMART_ID)) {
            throw new BadRequestException(INVALID_REQUEST, "Smart-ID authentication method is not allowed");
        }
    }
}
