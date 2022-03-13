// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash

var (
	// output size in bytes.
	size256 = 32
	size384 = 48
	size512 = 64

	// security level in bits.
	sec128 = 128
	sec192 = 192
	sec256 = 256
)

// parameters serves internal parameterization of the hash functions.
type parameters struct {
	blockSize  int
	outputSize int
	security   int
	name       string
}

// Identifier exposes general information about hashing functions.
type Identifier interface {
	Available() bool
	BlockSize() int
	Extendable() bool
	Hash(input ...[]byte) []byte
	SecurityLevel() int
	String() string
}
