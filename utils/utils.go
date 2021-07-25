// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package utils provides some wrappers to commonly used functions.
package utils

import (
	cryptorand "crypto/rand"
	"fmt"
)

const (
	bufLen = 100
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

// Concatenate takes the variadic array of input and returns a concatenation of it.
func Concatenate(length int, input ...[]byte) []byte {
	if len(input) == 0 {
		return nil
	}

	if len(input) == 1 {
		return input[0]
	}

	if length == 0 {
		length = bufLen
	}

	buf := make([]byte, 0, length)
	l := 0

	for _, in := range input {
		l += len(in)
		buf = append(buf, in...)
	}

	return buf
}
