package ee.ria.taraauthserver.utils;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.FIELD})
@Constraint(validatedBy = Iso3166Alpha2CountryCodesValidator.class)
public @interface Iso3166Alpha2CountryCodes {
    String message() default "Invalid ISO 3166-1 alpha-2 country list";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
