package ee.ria.taraauthserver.utils;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Iso3166Alpha2CountryCodesValidatorTest {

    private Iso3166Alpha2CountryCodesValidator validator;

    @Mock
    private ConstraintValidatorContext context;

    @Mock
    private ConstraintValidatorContext.ConstraintViolationBuilder violationBuilder;

    @BeforeEach
    void setUp() {
        validator = new Iso3166Alpha2CountryCodesValidator();
    }

    @Test
    void isValid_NullList_ReturnsTrue() {
        assertThat(validator.isValid(null, context)).isTrue();
    }

    @Test
    void isValid_EmptyList_ReturnsTrue() {
        assertThat(validator.isValid(List.of(), context)).isTrue();
    }

    @Test
    void isValid_SingleValidCountryCode_ReturnsTrue() {
        assertThat(validator.isValid(List.of("EE"), context)).isTrue();
    }

    @Test
    void isValid_MultipleValidCountryCodes_ReturnsTrue() {
        assertThat(validator.isValid(List.of("EE", "LV", "LT"), context)).isTrue();
    }

    @Test
    void isValid_SingleInvalidCountryCode_ReturnsFalse() {
        when(context.buildConstraintViolationWithTemplate(anyString())).thenReturn(violationBuilder);

        assertThat(validator.isValid(List.of("XX"), context)).isFalse();

        verify(context).disableDefaultConstraintViolation();
        verify(context).buildConstraintViolationWithTemplate("The following values are not valid ISO 3166-1 alpha-2 codes: [XX]");
    }

    @Test
    void isValid_MixOfValidAndInvalidCountryCodes_ReturnsFalse() {
        when(context.buildConstraintViolationWithTemplate(anyString())).thenReturn(violationBuilder);

        assertThat(validator.isValid(List.of("EE", "XX", "LV"), context)).isFalse();

        verify(context).disableDefaultConstraintViolation();
    }

    @Test
    void isValid_AllValidCountryCodes_DoesNotDisableDefaultConstraint() {
        validator.isValid(List.of("EE", "FI", "DE"), context);

        verify(context, never()).disableDefaultConstraintViolation();
    }

    @Test
    void isValid_LowercaseCountryCode_ReturnsFalse() {
        when(context.buildConstraintViolationWithTemplate(anyString())).thenReturn(violationBuilder);

        assertThat(validator.isValid(List.of("ee"), context)).isFalse();
    }
}
