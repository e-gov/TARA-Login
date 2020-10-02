package ee.ria.taraauthserver.error;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorMessages {
    INVALID_PHONE_NUMBER("message.mid-rest.error.invalid-phone-number"),
    INVALID_ID_CODE("message.mid-rest.error.invalid-identity-code"),
    MID_INTERNAL_ERROR("message.mid-rest.error.internal-error"),
    MID_USER_CANCEL("message.mid-rest.error.user-cancel"),
    MID_HASH_MISMATCH("message.mid-rest.error.signature-hash-mismatch"),
    MID_PHONE_ABSENT("message.mid-rest.error.phone-absent"),
    MID_DELIVERY_ERROR("message.mid-rest.error.delivery-error"),
    MID_SIM_ERROR("message.mid-rest.error.sim-error"),
    MID_TRANSACTION_EXPIRED("message.mid-rest.error.expired-transaction"),
    MID_ERROR_GENERAL("message.error.general"),
    NOT_MID_CLIENT("message.mid-rest.error.not-mid-client");

    private final String message;
}
