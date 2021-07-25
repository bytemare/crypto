// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

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
