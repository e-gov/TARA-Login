package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.exceptions.TaraException;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
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
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.BINDING_ERRORS;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.MESSAGE;
import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;

@Slf4j
@Component
public class ErrorAttributes extends DefaultErrorAttributes {
    public static final String ERROR_ATTR_MESSAGE = "message";
    public static final String ERROR_ATTR_LOCALE = "locale";
    private final MessageSource messageSource;
    private final Locale defaultLocale;

    public ErrorAttributes(MessageSource messageSource, AuthConfigurationProperties configurationProperties) {
        this.messageSource = messageSource;
        this.defaultLocale = new Locale(configurationProperties.getDefaultLocale());
    }

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> attr = super.getErrorAttributes(webRequest, options.including(MESSAGE, BINDING_ERRORS));

        HttpStatus status = HttpStatus.valueOf((int) attr.get("status"));

        if (status.is5xxServerError()) {
            handle5xxError(webRequest, attr);
        } else if (status.is4xxClientError()) {
            handle4xxClientError(webRequest, attr);
        }

        Locale locale = defaultIfNull((Locale) webRequest.getAttribute(ERROR_ATTR_LOCALE, SCOPE_REQUEST), defaultLocale);
        attr.put(ERROR_ATTR_LOCALE, locale);
        attr.remove("errors");
        attr.put("incident_nr", MDC.get("trace.id"));

        return attr;
    }

    private void handle4xxClientError(WebRequest webRequest, Map<String, Object> attr) {
        Throwable error = getError(webRequest);
        if (isTaraErrorWithErrorCode(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, translateErrorCode(webRequest, ((TaraException) error).getErrorCode()));
        } else if (isBindingError(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, formatBindingErrors((BindException) error));
        }
    }

    private void handle5xxError(WebRequest webRequest, Map<String, Object> attr) {
        int status = (int) attr.get("status");
        Throwable error = getError(webRequest);
        if (status == 502 && isTaraErrorWithErrorCode(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, translateErrorCode(webRequest, ((TaraException) error).getErrorCode()));
        } else {
            attr.replace(ERROR_ATTR_MESSAGE, translateErrorCode(webRequest, ErrorCode.INTERNAL_ERROR));
        }
    }

    private boolean isTaraErrorWithErrorCode(Throwable error) {
        return error instanceof TaraException && ((TaraException) error).getErrorCode() != null;
    }

    @NotNull
    private String translateErrorCode(WebRequest webRequest, ErrorCode errorCode) {
        Locale locale = defaultIfNull((Locale) webRequest.getAttribute(ERROR_ATTR_LOCALE, SCOPE_REQUEST), defaultLocale);
        try {
            return messageSource.getMessage(errorCode.getMessage(), errorCode.getMessageParameters(), locale);
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