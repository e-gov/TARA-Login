package ee.ria.taraauthserver.utils;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static java.util.function.Predicate.not;

class Iso3166Alpha2CountryCodesValidator implements ConstraintValidator<Iso3166Alpha2CountryCodes, Collection<String>> {

    @Override
    public boolean isValid(final Collection<String> value, final ConstraintValidatorContext context) {
        if (value == null || value.isEmpty()) {
            return true;
        }

        Set<String> isoCountries = Set.of(Locale.getISOCountries());
        List<String> invalidCountries = value.stream()
                .filter(not(isoCountries::contains))
                .toList();

        if (!invalidCountries.isEmpty()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                    "The following values are not valid ISO 3166-1 alpha-2 codes: " + invalidCountries
            ).addConstraintViolation();
            return false;
        }

        return true;
    }
}
