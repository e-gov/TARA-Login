package ee.ria.taraauthserver.config.properties;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EudiConfigurationPropertiesTest {

    @Test
    void toString_leavesOutClientSecret() {
        EudiConfigurationProperties properties = new EudiConfigurationProperties();
        properties.setClientId("tara-login");
        properties.setClientSecret("eudiplo-client-secret-value");

        String description = properties.toString();

        assertTrue(description.contains("tara-login"));
        assertFalse(description.contains("eudiplo-client-secret-value"));
    }

    @Test
    void validateConfiguration_levelOfAssuranceMissing_throws() {
        EudiConfigurationProperties properties = new EudiConfigurationProperties();

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, properties::validateConfiguration);

        assertEquals("EUDI wallet level of assurance must be configured", exception.getMessage());
    }

    @Test
    void validateConfiguration_levelOfAssuranceSet_passes() {
        EudiConfigurationProperties properties = new EudiConfigurationProperties();
        properties.setLevelOfAssurance(LevelOfAssurance.HIGH);

        assertDoesNotThrow(properties::validateConfiguration);
    }

    @Test
    void validation_defaultNumericSettings_noViolations() {
        assertEquals(Set.of(), violatedProperties(validProperties()));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void validation_nonPositiveNumericSettings_rejected(int value) {
        EudiConfigurationProperties properties = validProperties();
        properties.setConnectionTimeoutMilliseconds(value);
        properties.setReadTimeoutMilliseconds(value);
        properties.setMaxConnectionsTotal(value);

        assertEquals(Set.of("connectionTimeoutMilliseconds", "readTimeoutMilliseconds", "maxConnectionsTotal"),
                violatedProperties(properties));
    }

    private static EudiConfigurationProperties validProperties() {
        EudiConfigurationProperties properties = new EudiConfigurationProperties();
        properties.setEudiploUrl("https://eudiplo.example.com");
        properties.setClientId("tara-login");
        properties.setClientSecret("eudiplo-client-secret-value");
        return properties;
    }

    private static Set<String> violatedProperties(EudiConfigurationProperties properties) {
        try (var validatorFactory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = validatorFactory.getValidator();
            return validator.validate(properties).stream()
                    .map(ConstraintViolation::getPropertyPath)
                    .map(Object::toString)
                    .collect(Collectors.toSet());
        }
    }
}
