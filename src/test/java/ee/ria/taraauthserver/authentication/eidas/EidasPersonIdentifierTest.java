package ee.ria.taraauthserver.authentication.eidas;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EidasPersonIdentifierTest {

    private static final String SHRUG_EMOJI = "\uD83E\uDD37";
    private static final String BOLD_CHARACTERS = "\uuD835\uDC1F\uD835\uDC28\uD835\uDC31";

    @Test
    void simplePersonIdentifier_parsedCorrectly() {
        EidasPersonIdentifier personIdentifier = EidasPersonIdentifier.parse("ES/AT/02635542Y");

        assertEquals("ES", personIdentifier.getCountryCode());
        assertEquals("AT", personIdentifier.getDestinationCountryCode());
        assertEquals("02635542Y", personIdentifier.getIdCode());
    }

    @Test
    void tooManyPartsPersonIdentifier_trailingPartsParsedAsPartsOfIdCode() {
        EidasPersonIdentifier personIdentifier = EidasPersonIdentifier.parse("ES/AT/ET/LV/LT/123");

        assertEquals("ES", personIdentifier.getCountryCode());
        assertEquals("AT", personIdentifier.getDestinationCountryCode());
        assertEquals("ET/LV/LT/123", personIdentifier.getIdCode());
    }

    @Test
    void idCodeContainsNonStandardCharacters_parsedCorrectly() {
        String idCode = "////\\ÕÜöä!@#$%^&*()`~¹ツΩ≈ç√∫˜µ≤≥÷和製漢語ด้้้้้็็็็็้้้้้็็็" + SHRUG_EMOJI + BOLD_CHARACTERS;
        EidasPersonIdentifier personIdentifier = EidasPersonIdentifier.parse("LT/EE/" + idCode);

        assertEquals("LT", personIdentifier.getCountryCode());
        assertEquals("EE", personIdentifier.getDestinationCountryCode());
        assertEquals(idCode, personIdentifier.getIdCode());
    }

    @Test
    void longPersonIdentifier_parsedCorrectly() {
        String idCode = "a".repeat(512);
        EidasPersonIdentifier personIdentifier = EidasPersonIdentifier.parse("AT/LT/" + idCode);

        assertEquals("AT", personIdentifier.getCountryCode());
        assertEquals("LT", personIdentifier.getDestinationCountryCode());
        assertEquals(idCode, personIdentifier.getIdCode());
    }

    @ParameterizedTest
    @MethodSource("invalidInputs")
    void invalidPersonIdentifier_InvalidArgumentExceptionThrown(InvalidInput input) {
        assertThrows(
                IllegalArgumentException.class,
                () -> EidasPersonIdentifier.parse(input.value()),
                "Expected IllegalArgumentException to be thrown for input \"" + input.value + "\", reason: " + input.comment());
    }

    static List<InvalidInput> invalidInputs() {
        return List.of(
                invalidInput("/AB/123", "Empty country code"),
                invalidInput("AB//123", "Empty destination country code"),
                invalidInput("AB/CD/", "Empty ID code"),
                invalidInput("AB/cd/123", "Invalid destination country code"),
                invalidInput("ab/CD/123", "Lower case country code"),
                invalidInput("1B/CD/123", "Digit in country code"),
                invalidInput("EST/CD/123", "Too long country code"),
                invalidInput("AB/CD", "Missing part")
        );
    }

    private static InvalidInput invalidInput(String input, String reason) {
        return new InvalidInput(input, reason);
    }

    record InvalidInput(String value, String comment) {}

}
