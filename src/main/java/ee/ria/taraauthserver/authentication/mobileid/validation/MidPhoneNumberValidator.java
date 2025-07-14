package ee.ria.taraauthserver.authentication.mobileid.validation;

import ee.sk.mid.MidInputUtil;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class MidPhoneNumberValidator implements ConstraintValidator<ValidMidPhoneNumber, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return MidInputUtil.isPhoneNumberValid(value);
    }

}
