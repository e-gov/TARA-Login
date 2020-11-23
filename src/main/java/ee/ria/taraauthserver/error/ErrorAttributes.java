package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.context.request.WebRequest;

import java.util.*;

import static java.lang.String.format;
import static java.lang.String.join;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.BINDING_ERRORS;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.MESSAGE;

@Slf4j
@Component
public class ErrorAttributes extends DefaultErrorAttributes {

    @Autowired
    private MessageSource messageSource;

    public static final String DEFAULT_INTERNAL_EXCEPTION_MSG = "message.error.internalError";

    // TODO handle org.springframework.context.NoSuchMessageException

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> attr = super.getErrorAttributes(webRequest, options.including(MESSAGE, BINDING_ERRORS));
        HttpStatus status = HttpStatus.valueOf((int) attr.get("status"));
        if (status.is5xxServerError()) {
            handle5xxError(webRequest, attr);
        } else if (status.is4xxClientError()) {
            handle4xxClientError(webRequest, attr);
        }

        attr.put("locale", webRequest.getLocale().toString());
        attr.remove("errors");
        return attr;
    }

    private void handle4xxClientError(WebRequest webRequest, Map<String, Object> attr) {
        Throwable error = getError(webRequest);
        if (isTaraErrorWithErrorCode(error)) {
            attr.replace("message", translateErrorCode(webRequest, ((TaraException) error).getMessageCode().getMessage()));
        } else if (isBindingError(error)) {
            attr.replace("message", formatBindingErrors((BindException)error));
        }
    }

    private void handle5xxError(WebRequest webRequest, Map<String, Object> attr) {
        int status = (int) attr.get("status");
        Throwable error = getError(webRequest);
        if (status == 502 && isTaraErrorWithErrorCode(error)) {
            attr.replace("message", translateErrorCode(webRequest, ((TaraException) error).getMessageCode().getMessage()));
        } else {
            attr.replace("message", translateErrorCode(webRequest, DEFAULT_INTERNAL_EXCEPTION_MSG));
        }
    }

    private boolean isTaraErrorWithErrorCode(Throwable error) {
        return error instanceof TaraException && ((TaraException) error).getMessageCode() != null;
    }

    @NotNull
    private String translateErrorCode(WebRequest webRequest, String errorCode) {
        Locale locale = webRequest.getHeader(HttpHeaders.ACCEPT) != null ? RequestUtils.getLocale() : Locale.ENGLISH;
        try {
            return messageSource.getMessage(errorCode, null, locale);
        } catch (NoSuchMessageException ex) {
            return "???" + errorCode + "???";
        }
    }

    private boolean isBindingError(Throwable error) {
        return error instanceof BindException;
    }

    private String formatBindingErrors(BindException bindException) {
        BindingResult bindingResult = bindException.getBindingResult();

        List<String> errors = new ArrayList<>();
        for (FieldError fe : bindingResult.getFieldErrors()) {
            errors.add(format("%s", fe.getDefaultMessage()));
        }
        for (ObjectError fe : bindingResult.getGlobalErrors()) {
            errors.add(format("%s", fe.getDefaultMessage()));
        }
        return join("; ", errors);
    }
}