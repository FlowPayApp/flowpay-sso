package handler

import (
	"errors"
	"unicode"
)

const passwordPolicyHint = "la contraseña debe tener mínimo 8 caracteres, incluyendo mayúscula, minúscula, número y símbolo"

func validatePasswordPolicy(password string) error {
	if len(password) < 8 {
		return errors.New(passwordPolicyHint)
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
		return errors.New(passwordPolicyHint)
	}
	return nil
}
