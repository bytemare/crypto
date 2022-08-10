// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
)

var (
	// ErrParamNilScalar indicates a forbidden nil or empty scalar.
	ErrParamNilScalar = errors.New("nil or empty scalar")

	// ErrParamScalarLength indicates an invalid scalar length.
	ErrParamScalarLength = errors.New("invalid scalar length")

	// ErrParamNilPoint indicated a forbidden nil or empty point.
	ErrParamNilPoint = errors.New("nil or empty point")

	// ErrCastElement indicates a failed attempt to cast to a point.
	ErrCastElement = errors.New("could not cast to same group element (wrong group ?)")

	// ErrCastScalar indicates a failed attempt to cast to a scalar.
	ErrCastScalar = errors.New("could not cast to same group scalar (wrong group ?)")

	// ErrIdentity indicates that the identity point (or point at infinity) has been encountered.
	ErrIdentity = errors.New("infinity/identity point")
)

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	random := make([]byte, length)
	if _, err := cryptorand.Read(random); err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return random
}
