package grpcserver

import (
	"reflect"

	ut "github.com/go-playground/universal-translator"
)

// CustomValidationError is a custom validation error mock
type CustomValidationError struct {
	FieldName string
}

// Error Interface implementations
func (e CustomValidationError) Error() string {
	return e.FieldName
}

// Field Interface implementation
func (e CustomValidationError) Field() string {
	return e.FieldName
}

// Tag Interface implementation
func (e CustomValidationError) Tag() string {
	return e.FieldName
}

// ActualTag Interface implementation
func (e CustomValidationError) ActualTag() string {
	return e.FieldName
}

// Value Interface implementation
func (e CustomValidationError) Value() interface{} {
	return e.FieldName
}

// Param Interface implementation
func (e CustomValidationError) Param() string {
	return e.FieldName
}

// Namespace Interface implementation
func (e CustomValidationError) Namespace() string {
	return e.FieldName
}

// StructNamespace Interface implementation
func (e CustomValidationError) StructNamespace() string {
	return e.FieldName
}

// StructField Interface implementation
func (e CustomValidationError) StructField() string {
	return e.FieldName
}

// Kind Interface implementation
func (e CustomValidationError) Kind() reflect.Kind {
	return 1
}

// Type Interface implementation
func (e CustomValidationError) Type() reflect.Type {
	return reflect.TypeOf(e.FieldName)
}

// Translate Interface implementation
func (e CustomValidationError) Translate(ut ut.Translator) string {
	return e.FieldName
}
