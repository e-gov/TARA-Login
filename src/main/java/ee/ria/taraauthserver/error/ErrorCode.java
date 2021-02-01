package ee.ria.taraauthserver.error;

import ee.sk.mid.exception.*;
import lombok.AllArgsConstructor;
import lombok.Getter;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.ProcessingException;
import java.net.UnknownHostException;
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
    INVALID_LEGAL_PERSON("label.legal-person.error.invalid-legal-person"),
    LEGAL_PERSON_X_ROAD_SERVICE_NOT_AVAILABLE("label.legal-person.error.service-not-available");

    private final String message;
}
