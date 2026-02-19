package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.error.exceptions.SidCountryNotAllowedException;
import ee.sk.smartid.exception.SessionSecretMismatchException;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.ProcessingException;
import lombok.experimental.UtilityClass;

import java.util.Map;
import java.util.Set;

import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.error.ErrorCode.SID_COUNTRY_NOT_ALLOWED;
import static ee.ria.taraauthserver.error.ErrorCode.SID_DOCUMENT_UNUSABLE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_INTERACTION_NOT_SUPPORTED;
import static ee.ria.taraauthserver.error.ErrorCode.SID_INTERNAL_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.SID_REQUEST_TIMEOUT;
import static ee.ria.taraauthserver.error.ErrorCode.SID_SESSION_TIMEOUT;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_ACCOUNT_NOT_FOUND;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_CONFIRMATIONMESSAGE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_DISPLAYTEXTANDPIN;
import static ee.ria.taraauthserver.error.ErrorCode.SID_VALIDATION_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.SID_WRONG_VC;
import static java.util.Map.entry;

@UtilityClass
public class SmartIdExceptionTranslator {

    private static final Map<Class<?>, ErrorCode> ERROR_CODES_BY_EXCEPTION_TYPE = Map.ofEntries(
            entry(InternalServerErrorException.class, SID_INTERNAL_ERROR),
            entry(ProcessingException.class, SID_REQUEST_TIMEOUT),
            entry(UserRefusedException.class, SID_USER_REFUSED),
            entry(SessionTimeoutException.class, SID_SESSION_TIMEOUT),
            entry(DocumentUnusableException.class, SID_DOCUMENT_UNUSABLE),
            entry(UserSelectedWrongVerificationCodeException.class, SID_WRONG_VC),
            entry(RequiredInteractionNotSupportedByAppException.class, SID_INTERACTION_NOT_SUPPORTED),
            entry(UserRefusedDisplayTextAndPinException.class, SID_USER_REFUSED_DISPLAYTEXTANDPIN),
            entry(UserAccountNotFoundException.class, SID_USER_ACCOUNT_NOT_FOUND),
            entry(UserRefusedConfirmationMessageException.class, SID_USER_REFUSED_CONFIRMATIONMESSAGE),
            entry(UserRefusedConfirmationMessageWithVerificationChoiceException.class,
                    SID_USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE),
            entry(ServiceNotAvailableException.class, SID_INTERNAL_ERROR),
            entry(UnprocessableSmartIdResponseException.class, SID_VALIDATION_ERROR),
            entry(CertificateLevelMismatchException.class, SID_VALIDATION_ERROR),
            entry(SessionSecretMismatchException.class, SID_VALIDATION_ERROR),
            entry(SidCountryNotAllowedException.class, SID_COUNTRY_NOT_ALLOWED)
    );

    private static final Set<ErrorCode> TECHNICAL_ERRORS = Set.of(
            ERROR_GENERAL, SID_INTERNAL_ERROR, SID_VALIDATION_ERROR);

    public static ErrorCode getErrorCode(Exception e) {
        return ERROR_CODES_BY_EXCEPTION_TYPE.getOrDefault(e.getClass(), ERROR_GENERAL);
    }

    public static boolean isTechnicalError(ErrorCode errorCode) {
        return TECHNICAL_ERRORS.contains(errorCode);
    }

}
