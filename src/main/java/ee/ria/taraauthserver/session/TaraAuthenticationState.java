package ee.ria.taraauthserver.session;

public enum TaraAuthenticationState {
    INIT_AUTH_PROCESS,
    AUTHENTICATION_SUCCESS,
    AUTHENTICATION_CANCELED,
    AUTHENTICATION_FAILED,
    INIT_MID,
    INIT_SID,
    POLL_MID_STATUS,
    POLL_MID_STATUS_CANCELED,
    POLL_SID_STATUS,
    POLL_SID_STATUS_CANCELED,
    COMPLETE,
    NATURAL_PERSON_AUTHENTICATION_COMPLETED,
    LEGAL_PERSON_AUTHENTICATION_INIT,
    GET_LEGAL_PERSON_LIST,
    LEGAL_PERSON_AUTHENTICATION_COMPLETED,
    NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT,
    CONSENT_NOT_REQUIRED,
    INIT_CONSENT_PROCESS,
    CONSENT_GIVEN,
    CONSENT_NOT_GIVEN,
    WAITING_EIDAS_RESPONSE
}