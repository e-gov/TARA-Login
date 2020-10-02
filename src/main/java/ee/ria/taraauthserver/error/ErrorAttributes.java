package ee.ria.taraauthserver.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.BINDING_ERRORS;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.MESSAGE;

@Slf4j
@Component
public class ErrorAttributes extends DefaultErrorAttributes {

    public static final String INTERNAL_EXCEPTION_MSG = "Something went wrong internally. Please consult server logs " +
            "for further details.";

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> attr = super.getErrorAttributes(webRequest, options.including(MESSAGE, BINDING_ERRORS));
        if (HttpStatus.valueOf((int) attr.get("status")).is5xxServerError()) {
            attr.replace("message", INTERNAL_EXCEPTION_MSG);
        }
        return attr;
    }
}