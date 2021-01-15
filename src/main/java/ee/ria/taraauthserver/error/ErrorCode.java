package ee.ria.taraauthserver.error;

import ee.sk.mid.exception.*;
import lombok.AllArgsConstructor;
import lombok.Getter;

import javax.ws.rs.InternalServerErrorException;
import java.util.HashMap;
import java.util.Map;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    INVALID_LOGIN_CHALLENGE("message.error.invalid-login-challenge"),
    NO_VALID_AUTHMETHODS_AVAILABLE("message.error.no-allowed-authmethods"),
    ESTEID_INVALID_REQUEST("message.idc.error"),
    MID_USER_CANCEL("message.mid-rest.error.user-cancel"),
    MID_HASH_MISMATCH("message.mid-rest.error.signature-hash-mismatch"),
    MID_PHONE_ABSENT("message.mid-rest.error.phone-absent"),
    MID_DELIVERY_ERROR("message.mid-rest.error.delivery-error"),
    MID_SIM_ERROR("message.mid-rest.error.sim-error"),
    MID_TRANSACTION_EXPIRED("message.mid-rest.error.expired-transaction"),
    NOT_MID_CLIENT("message.mid-rest.error.not-mid-client"),
    MID_INTERNAL_ERROR("message.mid-rest.error.internal-error"),
    MID_INTEGRATION_ERROR("message.error.general"),
    MID_VALIDATION_ERROR("message.mid-rest.error.validation-error"),
    ERROR_GENERAL("message.error.general"),
    SESSION_NOT_FOUND("message.error.session-not-found"),
    SESSION_STATE_INVALID("message.error.session-state-invalid"),
    INVALID_REQUEST("message.error.invalid-request"),
    LEGAL_PERSON_X_ROAD_SERVICE_NOT_AVAILABLE("label.legal-person.error.service-not-available");

    private final String message;

    public static Map<Class<?>, ErrorCode> errorMap;

    static {
        errorMap = new HashMap<>();
        errorMap.put(InternalServerErrorException.class, MID_INTERNAL_ERROR);
        errorMap.put(MidInternalErrorException.class, MID_INTERNAL_ERROR);
        errorMap.put(MidSessionNotFoundException.class, MID_INTEGRATION_ERROR);
        errorMap.put(MidMissingOrInvalidParameterException.class, MID_INTEGRATION_ERROR);
        errorMap.put(MidUnauthorizedException.class, MID_INTEGRATION_ERROR);
        errorMap.put(MidNotMidClientException.class, NOT_MID_CLIENT);
        errorMap.put(MidSessionTimeoutException.class, MID_TRANSACTION_EXPIRED);
        errorMap.put(MidUserCancellationException.class, MID_USER_CANCEL);
        errorMap.put(MidInvalidUserConfigurationException.class, MID_HASH_MISMATCH);
        errorMap.put(MidPhoneNotAvailableException.class, MID_PHONE_ABSENT);
        errorMap.put(MidDeliveryException.class, MID_DELIVERY_ERROR);
    }

    public static ErrorCode getErrorCode(Throwable ex) {
        return errorMap.getOrDefault(ex.getClass(), ERROR_GENERAL);
    }
}
