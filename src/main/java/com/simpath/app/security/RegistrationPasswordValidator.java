package com.simpath.app.security;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.nio.charset.StandardCharsets;

public class RegistrationPasswordValidator implements ConstraintValidator<RegistrationPassword, String> {
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value != null && value.length() <= 72 && !value.isBlank() && value.codePointCount(0, value.length()) >= 12
                && value.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
