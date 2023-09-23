package model

import (
	"reflect"

	ut "github.com/go-playground/universal-translator"
)

type CustomValidationError struct {
	FieldName string
}

func (e CustomValidationError) Error() string {
	return e.FieldName
}

func (e CustomValidationError) Field() string {
	return e.FieldName
}

func (e CustomValidationError) Tag() string {
	return e.FieldName
}

func (e CustomValidationError) ActualTag() string {
	return e.FieldName
}

func (e CustomValidationError) Value() interface{} {
	return e.FieldName
}

func (e CustomValidationError) Param() string {
	return e.FieldName
}

func (e CustomValidationError) Namespace() string {
	return e.FieldName
}

func (e CustomValidationError) StructNamespace() string {
	return e.FieldName
}

func (e CustomValidationError) StructField() string {
	return e.FieldName
}

func (e CustomValidationError) Kind() reflect.Kind {
	return 1
}

func (e CustomValidationError) Type() reflect.Type {
	return reflect.TypeOf(e.FieldName)
}

func (e CustomValidationError) Translate(ut ut.Translator) string {
	return e.FieldName
}
