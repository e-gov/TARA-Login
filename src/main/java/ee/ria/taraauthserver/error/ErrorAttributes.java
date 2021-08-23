package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.error.exceptions.TaraException;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.RequiredArgsConstructor;
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

import static ee.ria.taraauthserver.security.RequestCorrelationFilter.MDC_ATTRIBUTE_TRACE_ID;
import static java.lang.String.format;
import static java.lang.String.join;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.BINDING_ERRORS;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.MESSAGE;
import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;
import static ee.ria.taraauthserver.error.ErrorCode.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class ErrorAttributes extends DefaultErrorAttributes {
    public static final String ERROR_ATTR_MESSAGE = "message";
    public static final String ERROR_ATTR_LOCALE = "locale";
    public static final String ERROR_ATTR_LOGIN_CHALLENGE = "login_challenge";
    public static final String ERROR_ATTR_INCIDENT_NR = "incident_nr";
    public static final String ERROR_ATTR_REPORTABLE = "reportable";
    private final MessageSource messageSource;

    public static final Set<ErrorCode> reportableErrors;

    static {
        reportableErrors = new HashSet<>();
        reportableErrors.add(EIDAS_AUTHENTICATION_FAILED);
        reportableErrors.add(EIDAS_INTERNAL_ERROR);
        reportableErrors.add(INVALID_OIDC_CLIENT);
        reportableErrors.add(INVALID_OIDC_REQUEST);
        reportableErrors.add(INVALID_CSRF_TOKEN);
        reportableErrors.add(SESSION_STATE_INVALID);
        reportableErrors.add(ERROR_GENERAL);
        reportableErrors.add(MID_INTEGRATION_ERROR);
        reportableErrors.add(INTERNAL_ERROR);
        reportableErrors.add(MID_HASH_MISMATCH);
        reportableErrors.add(INVALID_LOGIN_CHALLENGE);
        reportableErrors.add(ESTEID_INVALID_REQUEST);
        reportableErrors.add(NO_VALID_AUTHMETHODS_AVAILABLE);
        reportableErrors.add(MID_INTERNAL_ERROR);
        reportableErrors.add(SID_INTERNAL_ERROR);
        reportableErrors.add(SID_REQUEST_TIMEOUT);
        reportableErrors.add(SID_INTERACTION_NOT_SUPPORTED);
        reportableErrors.add(EIDAS_COUNTRY_NOT_SUPPORTED);
        reportableErrors.add(IDC_CERT_NOT_YET_VALID);
        reportableErrors.add(IDC_OCSP_NOT_AVAILABLE);
        reportableErrors.add(LEGAL_PERSON_X_ROAD_SERVICE_NOT_AVAILABLE);
        reportableErrors.add(MISSING_SCOPE);
        reportableErrors.add(IDC_UNKNOWN);
        reportableErrors.add(INVALID_REQUEST);
        reportableErrors.add(INVALID_LEGAL_PERSON);
        reportableErrors.add(MID_VALIDATION_ERROR);
    }

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> attr = super.getErrorAttributes(webRequest, options.including(MESSAGE, BINDING_ERRORS));

        HttpStatus status = HttpStatus.resolve((int) attr.get("status"));
        if (status == null || status.is5xxServerError()) {
            handle5xxError(webRequest, attr);
        } else if (status.is4xxClientError()) {
            handle4xxClientError(webRequest, attr);
        }

        Locale locale = RequestUtils.getLocale();
        attr.put(ERROR_ATTR_LOCALE, locale);
        attr.put(ERROR_ATTR_LOGIN_CHALLENGE, webRequest.getAttribute(ERROR_ATTR_LOGIN_CHALLENGE, SCOPE_REQUEST));
        attr.put(ERROR_ATTR_INCIDENT_NR, MDC.get(MDC_ATTRIBUTE_TRACE_ID));
        attr.put(ERROR_ATTR_REPORTABLE, isReportable(getError(webRequest), status));
        attr.remove("errors");
        return attr;
    }

    private boolean isReportable(Throwable error, HttpStatus status) {

        if (status == null || status.is5xxServerError())
            return true;
        else if (isTaraErrorWithErrorCode(error)) {
            ErrorCode errorCode = ((TaraException) error).getErrorCode();
            return reportableErrors.contains(errorCode);
        } else
            return false;
    }

    private void handle4xxClientError(WebRequest webRequest, Map<String, Object> attr) {
        Throwable error = getError(webRequest);
        if (isTaraErrorWithErrorCode(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, translateErrorCode(((TaraException) error).getErrorCode()));
        } else if (isBindingError(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, formatBindingErrors((BindException) error));
        }
    }

    private void handle5xxError(WebRequest webRequest, Map<String, Object> attr) {
        int status = (int) attr.get("status");
        Throwable error = getError(webRequest);
        if (status == 502 && isTaraErrorWithErrorCode(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, translateErrorCode(((TaraException) error).getErrorCode()));
        } else {
            attr.replace(ERROR_ATTR_MESSAGE, translateErrorCode(ErrorCode.INTERNAL_ERROR));
        }
    }

    private boolean isTaraErrorWithErrorCode(Throwable error) {
        return error instanceof TaraException && ((TaraException) error).getErrorCode() != null;
    }

    @NotNull
    private String translateErrorCode(ErrorCode errorCode) {
        Locale locale = RequestUtils.getLocale();
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