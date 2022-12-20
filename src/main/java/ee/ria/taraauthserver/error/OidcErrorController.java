package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.constraints.Size;
import java.util.Map;

import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;

@Controller
public class OidcErrorController {

    public static final Map<String, ErrorCode> oidcErrorsMap = Map.of(
            "invalid_client", ErrorCode.INVALID_OIDC_CLIENT,
            "invalid_request", ErrorCode.INVALID_OIDC_REQUEST);

    @GetMapping(value = "/oidc-error")
    public ModelAndView handleExternalErrors(
            @RequestParam(name = "error", required = false)
            @Size(max = 50) String errorCode,
            @RequestParam(name = "error_description", required = false) String errorDescription,
            @RequestParam(name = "error_hint", required = false) String errorHint) {
        if (errorCode == null) {
            throw new BadRequestException(ERROR_GENERAL, "Request parameter 'error' must not be null");
        }
        if (oidcErrorsMap.containsKey(errorCode)) {
            throw new BadRequestException(oidcErrorsMap.get(errorCode), String.format("Oidc server error: code = %s, description = %s, hint = %s", errorCode, errorDescription, errorHint));
        } else {
            throw new IllegalStateException("Unknown error code encountered");
        }
    }

}
