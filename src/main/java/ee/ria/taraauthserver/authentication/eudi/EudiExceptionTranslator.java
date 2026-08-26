package ee.ria.taraauthserver.authentication.eudi;

import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.EudiploSession;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.EudiploSession.StatusEnum;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.TaraException;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Set;

import static ee.ria.taraauthserver.error.ErrorCode.EUDI_CALLBACK_INVALID;
import static ee.ria.taraauthserver.error.ErrorCode.EUDI_INTERNAL_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.EUDI_PRESENTATION_REJECTED;
import static ee.ria.taraauthserver.error.ErrorCode.EUDI_TIMEOUT;
import static ee.ria.taraauthserver.error.ErrorCode.EUDI_USER_CANCEL;

@UtilityClass
public class EudiExceptionTranslator {

    /**
     * EUDI_CALLBACK_INVALID is caused by whoever produced the callback or response, not by TARA or eudiplo.
     */
    private static final Set<ErrorCode> USER_ERRORS = Set.of(
            EUDI_USER_CANCEL,
            EUDI_TIMEOUT,
            EUDI_PRESENTATION_REJECTED,
            EUDI_CALLBACK_INVALID);

    /**
     * The OAuth error a wallet returns when the user declines to present, stored by eudiplo as {@code failureCode}.
     */
    static final String FAILURE_CODE_ACCESS_DENIED = "access_denied";

    /**
     * eudiplo could not load its own trust list, so the presentation was never checked and the failure is eudiplo's.
     */
    static final String FAILURE_CODE_TRUST_LIST_UNAVAILABLE = "trust_list_unavailable";

    public static ErrorCode getErrorCode(Exception e) {
        if (e instanceof TaraException taraException) {
            return taraException.getErrorCode();
        }
        return EUDI_INTERNAL_ERROR;
    }

    public static boolean isTechnicalError(ErrorCode errorCode) {
        return !USER_ERRORS.contains(errorCode);
    }

    /**
     * @return {@code null} while the session waits for the wallet or once it has completed. TARA never cancels sessions,
     * so a {@code cancelled} one was cancelled by an operator and is a technical error.
     */
    public static ErrorCode getErrorCodeForSession(EudiploSession presentationSession, Instant now) {
        return switch (presentationSession.getStatus()) {
            case ACTIVE, FETCHED -> isExpired(presentationSession, now) ? EUDI_TIMEOUT : null;
            case COMPLETED -> null;
            case FAILED -> getErrorCodeForFailure(presentationSession.getFailureCode());
            case EXPIRED -> EUDI_TIMEOUT;
            case CANCELLED -> EUDI_INTERNAL_ERROR;
        };
    }

    /**
     * eudiplo rejects the wallet as soon as {@code expiresAt} passes, but records the {@code expired} status only in a
     * periodic maintenance job, so a session that still waits is checked against {@code expiresAt} here.
     *
     * @return {@code false} for a session without {@code expiresAt}, which has no lifetime
     */
    public static boolean isExpired(EudiploSession presentationSession, Instant now) {
        OffsetDateTime expiresAt = presentationSession.getExpiresAt();
        return expiresAt != null && !expiresAt.toInstant().isAfter(now);
    }

    /**
     * Never anything else of the session, which carries the presented PID claims.
     */
    public static String describeEndedSession(EudiploSession presentationSession) {
        StatusEnum status = presentationSession.getStatus();
        if (status == StatusEnum.ACTIVE || status == StatusEnum.FETCHED) {
            return "eudiplo presentation session %s expired at %s in status %s"
                    .formatted(presentationSession.getId(), presentationSession.getExpiresAt(), status);
        }
        StringBuilder description = new StringBuilder("eudiplo presentation session %s ended in status %s"
                .formatted(presentationSession.getId(), status));
        if (presentationSession.getFailureCode() != null) {
            description.append(", failure code ").append(presentationSession.getFailureCode());
        }
        if (presentationSession.getErrorReason() != null) {
            description.append(": ").append(presentationSession.getErrorReason());
        }
        return description.toString();
    }

    private static ErrorCode getErrorCodeForFailure(String failureCode) {
        if (FAILURE_CODE_ACCESS_DENIED.equals(failureCode)) {
            return EUDI_USER_CANCEL;
        }
        if (FAILURE_CODE_TRUST_LIST_UNAVAILABLE.equals(failureCode)) {
            return EUDI_INTERNAL_ERROR;
        }
        return EUDI_PRESENTATION_REJECTED;
    }

}
