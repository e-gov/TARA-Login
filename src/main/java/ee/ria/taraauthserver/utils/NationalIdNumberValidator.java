package ee.ria.taraauthserver.utils;

import ee.sk.mid.MidNationalIdentificationCodeValidator;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.beans.BeanWrapperImpl;

public class NationalIdNumberValidator implements ConstraintValidator<ValidNationalIdNumber, Object> {

    private String fieldName;
    private String dependFieldName;

    @Override
    public void initialize(ValidNationalIdNumber annotation) {
        fieldName          = annotation.fieldName();
        dependFieldName    = annotation.dependFieldName();
    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        if (value == null) {
            return false;
        }
        BeanWrapperImpl wrapper = new BeanWrapperImpl(value);
  
        String fieldValue       = String.valueOf(wrapper.getPropertyValue(fieldName));
        String dependFieldValue = String.valueOf(wrapper.getPropertyValue(dependFieldName));
    
        if (dependFieldValue.equals("EE") || dependFieldValue.equals("LT")) {
            return MidNationalIdentificationCodeValidator.isValid(fieldValue);
        } else {
            return true;
        }
    }
}
