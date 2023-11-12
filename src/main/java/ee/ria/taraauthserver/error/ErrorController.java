package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.error.exceptions.AuthFlowTimeoutException;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.constraints.Size;

@Slf4j
@Controller
public class ErrorController {

    private static final String AUTH_FLOW_TIMEOUT = "auth_flow_timeout";
    private static final String INVALID_OIDC_CLIENT = "invalid_client";
    private static final String INVALID_OIDC_REQUEST = "invalid_request";

    @GetMapping(value = "/oidc-error")
    public ModelAndView handleOidcErrors(
            @RequestParam(name = "error", required = false)
            @Size(max = 50) String errorCode,
            @RequestParam(name = "error_description", required = false) String errorDescription,
            @RequestParam(name = "error_hint", required = false) String errorHint) {
        if (errorCode == null) {
            throw new BadRequestException(ErrorCode.ERROR_GENERAL, "Request parameter 'error' must not be null");
        } else {
            switch (errorCode) {
                case INVALID_OIDC_CLIENT:
                    throw new BadRequestException( ErrorCode.INVALID_OIDC_CLIENT, String.format("Oidc server error: code = %s, description = %s, hint = %s", errorCode, errorDescription, errorHint));
                case INVALID_OIDC_REQUEST:
                    throw new BadRequestException( ErrorCode.INVALID_OIDC_REQUEST, String.format("Oidc server error: code = %s, description = %s, hint = %s", errorCode, errorDescription, errorHint));
                default:
                    throw new IllegalStateException("Unknown error code encountered");
            }
        }
    }

    @GetMapping(value = "/error-handler")
    public ModelAndView handleErrors(
            @RequestParam(name = "error_code", required = false) @Size(max = 50) String errorCode) {
        if (errorCode == null) {
            throw new BadRequestException(ErrorCode.ERROR_GENERAL, "Request parameter 'error_code' must not be null");
        } else {
            switch (errorCode) {
                case AUTH_FLOW_TIMEOUT:
                    throw new AuthFlowTimeoutException("User did not authenticate before the login session timeout");
                default:
                    throw new IllegalStateException("Unknown error code encountered");
            }
        }
    }

}
