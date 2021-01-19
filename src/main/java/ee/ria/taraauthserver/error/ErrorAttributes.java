package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.error.exceptions.TaraException;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.session.SessionRepository;
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

    public static final String ATTR_MESSAGE = "message";
    @Autowired
    private MessageSource messageSource;

    public static final String DEFAULT_INTERNAL_EXCEPTION_MSG = "message.error.internal-error";

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

        attr.put("locale", RequestUtils.getLocale());
        attr.remove("errors");
        attr.put("incident_nr", MDC.get("traceId"));
        return attr;
    }

    private void handle4xxClientError(WebRequest webRequest, Map<String, Object> attr) {
        Throwable error = getError(webRequest);
        if (isTaraErrorWithErrorCode(error)) {
            attr.replace(ATTR_MESSAGE, translateErrorCode(webRequest, ((TaraException) error).getErrorCode().getMessage()));
        } else if (isBindingError(error)) {
            attr.replace(ATTR_MESSAGE, formatBindingErrors((BindException) error));
        }
    }

    private void handle5xxError(WebRequest webRequest, Map<String, Object> attr) {
        int status = (int) attr.get("status");
        Throwable error = getError(webRequest);
        if (status == 502 && isTaraErrorWithErrorCode(error)) {
            attr.replace(ATTR_MESSAGE, translateErrorCode(webRequest, ((TaraException) error).getErrorCode().getMessage()));
        } else {
            attr.replace(ATTR_MESSAGE, translateErrorCode(webRequest, DEFAULT_INTERNAL_EXCEPTION_MSG));
        }
    }

    private boolean isTaraErrorWithErrorCode(Throwable error) {
        return error instanceof TaraException && ((TaraException) error).getErrorCode() != null;
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
        Collections.sort(errors);
        return join("; ", errors);
    }
}