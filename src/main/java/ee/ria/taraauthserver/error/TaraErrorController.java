package ee.ria.taraauthserver.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.BINDING_ERRORS;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.MESSAGE;

@Slf4j
@Controller
public class TaraErrorController implements ErrorController {

    private final ErrorAttributes errorAttributes;

    public TaraErrorController(ErrorAttributes errorAttributes) {
        this.errorAttributes = errorAttributes;
    }

    @RequestMapping(path = "/error", produces = MediaType.TEXT_HTML_VALUE)
    public String handleHtmlError(Model model, WebRequest webRequest) {
        Map<String, Object> attr = errorAttributes.getErrorAttributes(webRequest, ErrorAttributeOptions.defaults().including(MESSAGE, BINDING_ERRORS));
        model.addAllAttributes(attr);
        return "error";
    }

    @RequestMapping("/error")
    public ResponseEntity<Map<String, Object>> handleError(WebRequest webRequest) {
        Map<String, Object> body = errorAttributes.getErrorAttributes(webRequest, ErrorAttributeOptions.defaults().including(MESSAGE, BINDING_ERRORS));
        return new ResponseEntity<>(body, HttpStatus.valueOf((Integer) body.getOrDefault("status", 500)));
    }

    @Override
    public String getErrorPath() {
        return null;
    }
}