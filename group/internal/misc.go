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
	ErrParamNilScalar    = errors.New("nil or empty scalar")
	ErrParamScalarLength = errors.New("invalid scalar length")
	ErrParamNilPoint     = errors.New("nil or empty point")
	ErrCastElement       = errors.New("could not cast to same group element (wrong group ?)")
	ErrCastScalar        = errors.New("could not cast to same group scalar (wrong group ?)")
)

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	r := make([]byte, length)
	if _, err := cryptorand.Read(r); err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return r
}
