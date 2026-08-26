package ee.ria.taraauthserver.authentication.eudi;

import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.EudiploSession;
import ee.ria.taraauthserver.error.exceptions.EudiPresentationFailedException;
import tools.jackson.databind.JsonNode;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.List;

import static ee.ria.taraauthserver.error.ErrorCode.EUDI_INTERNAL_ERROR;

/**
 * The PID claims that a completed eudiplo presentation session carries. All of them are mandatory.
 */
record EudiPidClaims(String personalAdministrativeNumber,
                     String issuingCountry,
                     String givenName,
                     String familyName,
                     LocalDate birthDate) {

    private static final String CLAIM_FAMILY_NAME = "family_name";
    private static final String CLAIM_GIVEN_NAME = "given_name";
    private static final String CLAIM_BIRTH_DATE = "birth_date";
    private static final String CLAIM_PERSONAL_ADMINISTRATIVE_NUMBER = "personal_administrative_number";
    private static final String CLAIM_ISSUING_COUNTRY = "issuing_country";

    static EudiPidClaims from(EudiploSession completedSession) {
        JsonNode pid = getPresentedPid(completedSession);
        return new EudiPidClaims(
                requireClaim(pid, CLAIM_PERSONAL_ADMINISTRATIVE_NUMBER),
                requireClaim(pid, CLAIM_ISSUING_COUNTRY),
                requireClaim(pid, CLAIM_GIVEN_NAME),
                requireClaim(pid, CLAIM_FAMILY_NAME),
                parseDateOfBirth(requireClaim(pid, CLAIM_BIRTH_DATE)));
    }

    /**
     * eudiplo strips the namespace from mdoc claims, so the PID elements are top-level fields of {@code values[0]}.
     */
    private static JsonNode getPresentedPid(EudiploSession presentationSession) {
        List<JsonNode> credentials = presentationSession.getCredentials();
        if (credentials == null || credentials.size() != 1) {
            throw new EudiPresentationFailedException(EUDI_INTERNAL_ERROR,
                    "Presentation session %s carries %d presented credential sets instead of one"
                            .formatted(presentationSession.getId(), credentials == null ? 0 : credentials.size()));
        }
        JsonNode pid = credentials.get(0).path("values").path(0);
        if (!pid.isObject()) {
            throw new EudiPresentationFailedException(EUDI_INTERNAL_ERROR,
                    "Presentation session %s carries no presented credential values"
                            .formatted(presentationSession.getId()));
        }
        return pid;
    }

    private static String findClaim(JsonNode pid, String element) {
        JsonNode value = pid.path(element);
        return value.isValueNode() && !value.isNull() ? value.asString() : null;
    }

    private static String requireClaim(JsonNode pid, String element) {
        String value = findClaim(pid, element);
        if (value == null || value.isBlank()) {
            throw new EudiPresentationFailedException(EUDI_INTERNAL_ERROR,
                    "Presented PID is missing mandatory claim \"%s\"".formatted(element));
        }
        return value;
    }

    private static LocalDate parseDateOfBirth(String birthDate) {
        try {
            return LocalDate.parse(birthDate);
        } catch (DateTimeParseException e) {
            throw new EudiPresentationFailedException(EUDI_INTERNAL_ERROR,
                    "Presented PID birth_date is not an ISO date");
        }
    }

}
