package ee.ria.taraauthserver.utils;

import ee.sk.mid.MidNationalIdentificationCodeValidator;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class NationalIdNumberValidator implements ConstraintValidator<ValidNationalIdNumber, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return MidNationalIdentificationCodeValidator.isValid(value);
    }
}
