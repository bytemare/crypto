package internal

import (
	"errors"
	"fmt"
)

const (
	errParams = "parameter error"
)

// ParameterError returns an error indicating an error with parameters.
func ParameterError(err string) error {
	return NewError(errParams, err)
}

// NewError returns an error prefixed with prefix and embedding err as an error.
func NewError(prefix, err string) error {
	return fmt.Errorf("%s : %w", prefix, errors.New(err))
}
