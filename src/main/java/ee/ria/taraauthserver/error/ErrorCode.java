package ee.ria.taraauthserver.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@RequiredArgsConstructor
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
    IDC_OCSP_NOT_AVAILABLE("message.idc.error.ocsp.not.available"),
    IDC_CERT_NOT_YET_VALID("message.idc.cert-not-yet-valid"),
    IDC_CERT_EXPIRED("message.idc.cert-expired"),
    IDC_CERTIFICATE_FAILED("message.idc.certificate-failed"),
    IDC_DOES_ID_CARD_EXIST("message.idc.does-id-card-exist"),
    IDC_NO_CERTIFICATE("message.idc.no-certificate"),
    IDC_REVOKED("message.idc.revoked"),
    IDC_UNKNOWN("message.idc.unknown"),
    ERROR_GENERAL("message.error.general"),
    SESSION_NOT_FOUND("message.error.session-not-found"),
    SESSION_STATE_INVALID("message.error.session-state-invalid"),
    INVALID_REQUEST("message.error.invalid-request"),
    INVALID_LEGAL_PERSON("label.legal-person.error.invalid-legal-person"),
    LEGAL_PERSON_X_ROAD_SERVICE_NOT_AVAILABLE("label.legal-person.error.service-not-available"),
    INTERNAL_ERROR("message.error.internal-error"),
    EIDAS_COUNTRY_NOT_SUPPORTED("message.eidas.not-allowed-country"),
    EIDAS_USER_CONSENT_NOT_GIVEN("message.eidas.error.user-consent-not-given"),
    EIDAS_AUTHENTICATION_FAILED("message.eidas.error.authentication-failed"),
    EIDAS_INTERNAL_ERROR("message.eidas.error.internal-error");

    private final String message;
    @Setter
    private Object[] content;
}
