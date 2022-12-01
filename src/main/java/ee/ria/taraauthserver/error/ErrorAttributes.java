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

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static ee.ria.taraauthserver.error.ErrorCode.EIDAS_USER_CONSENT_NOT_GIVEN;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_WEBEID_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_CSRF_TOKEN;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_GOVSSO_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.error.ErrorCode.MID_DELIVERY_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.MID_PHONE_ABSENT;
import static ee.ria.taraauthserver.error.ErrorCode.MID_SIM_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.MID_TRANSACTION_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.MID_USER_CANCEL;
import static ee.ria.taraauthserver.error.ErrorCode.NOT_MID_CLIENT;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_STATE_INVALID;
import static ee.ria.taraauthserver.error.ErrorCode.SID_DOCUMENT_UNUSABLE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_SESSION_TIMEOUT;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_ACCOUNT_NOT_FOUND;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_CERT_CHOICE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_CONFIRMATIONMESSAGE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_DISAPLAYTEXTANDPIN;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_VC_CHOICE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_WRONG_VC;
import static ee.ria.taraauthserver.security.RequestCorrelationFilter.MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID;
import static java.lang.String.format;
import static java.lang.String.join;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.BINDING_ERRORS;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.MESSAGE;
import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;

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

    public static final Set<ErrorCode> notReportableErrors = EnumSet.of(
            MID_USER_CANCEL,
            MID_PHONE_ABSENT,
            MID_DELIVERY_ERROR,
            MID_SIM_ERROR,
            MID_TRANSACTION_EXPIRED,
            NOT_MID_CLIENT,
            SID_USER_REFUSED,
            SID_SESSION_TIMEOUT,
            SID_WRONG_VC,
            SID_USER_REFUSED_CERT_CHOICE,
            SID_USER_REFUSED_DISAPLAYTEXTANDPIN,
            SID_USER_ACCOUNT_NOT_FOUND,
            SID_USER_REFUSED_VC_CHOICE,
            SID_USER_REFUSED_CONFIRMATIONMESSAGE,
            SID_USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE,
            IDC_CERT_EXPIRED,
            IDC_REVOKED,
            IDC_WEBEID_NOT_AVAILABLE,
            EIDAS_USER_CONSENT_NOT_GIVEN,
            SID_DOCUMENT_UNUSABLE,
            SESSION_NOT_FOUND,
            SESSION_STATE_INVALID,
            INVALID_REQUEST,
            INVALID_CSRF_TOKEN,
            INVALID_LOGIN_CHALLENGE,
            INVALID_GOVSSO_LOGIN_CHALLENGE
    );

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> attr = super.getErrorAttributes(webRequest, options.including(MESSAGE, BINDING_ERRORS));
        HttpStatus status = HttpStatus.resolve((int) attr.get("status"));
        Throwable error = getError(webRequest);

        if (status == null || status.is5xxServerError()) {
            handle5xxError(error, attr);
        } else if (status.is4xxClientError()) {
            handle4xxClientError(error, attr);
        }

        Locale locale = RequestUtils.getLocale();
        attr.put(ERROR_ATTR_LOCALE, locale);
        attr.put(ERROR_ATTR_LOGIN_CHALLENGE, webRequest.getAttribute(ERROR_ATTR_LOGIN_CHALLENGE, SCOPE_REQUEST));
        attr.put(ERROR_ATTR_INCIDENT_NR, MDC.get(MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID));
        attr.put(ERROR_ATTR_REPORTABLE, isReportable(error, status));
        attr.remove("errors");
        return attr;
    }

    private boolean isReportable(Throwable error, HttpStatus status) {

        if (status == null || status.is5xxServerError())
            return true;
        else if (isTaraErrorWithErrorCode(error)) {
            ErrorCode errorCode = ((TaraException) error).getErrorCode();
            return !notReportableErrors.contains(errorCode);
        } else
            return false;
    }

    private void handle4xxClientError(Throwable error, Map<String, Object> attr) {
        if (isTaraErrorWithErrorCode(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, translateTaraErrorMessage((TaraException) error));
        } else if (isBindingError(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, formatBindingErrors((BindException) error));
        }
    }

    private void handle5xxError(Throwable error, Map<String, Object> attr) {
        int status = (int) attr.get("status");
        if (status == 502 && isTaraErrorWithErrorCode(error)) {
            attr.replace(ERROR_ATTR_MESSAGE, translateTaraErrorMessage((TaraException) error));
        } else {
            attr.replace(ERROR_ATTR_MESSAGE, translateErrorCode(ErrorCode.INTERNAL_ERROR, null));
        }
    }

    private boolean isTaraErrorWithErrorCode(Throwable error) {
        return error instanceof TaraException && ((TaraException) error).getErrorCode() != null;
    }

    private String translateTaraErrorMessage(TaraException taraException) {
        return translateErrorCode(taraException.getErrorCode(), taraException.getErrorCodeMessageParameters());
    }

    @NotNull
    private String translateErrorCode(ErrorCode errorCode, String[] messageParameters) {
        Locale locale = RequestUtils.getLocale();
        try {
            return messageSource.getMessage(errorCode.getMessage(), messageParameters, locale);
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
