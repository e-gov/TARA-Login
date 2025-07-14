package ee.ria.taraauthserver.authentication.mobileid.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({FIELD, METHOD, PARAMETER, ANNOTATION_TYPE})
@Retention(RUNTIME)
@Constraint(validatedBy = MidPhoneNumberValidator.class)
@Documented
public @interface ValidMidPhoneNumber {

    String message() default "Invalid Mobile-ID phone number";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}
