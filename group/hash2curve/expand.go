// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package hash2curve provides hash-to-curve compatible hashing over arbitrary input.
package hash2curve

import (
	"crypto"
	"errors"
	"hash"

	x "github.com/bytemare/cryptotools/hash"
)

const (
	dstMaxLength  = 255
	dstLongPrefix = "H2C-OVERSIZE-DST-"

	minLength            = 0
	recommendedMinLength = 16
)

var errZeroLenDST = errors.New("zero-length DST")

// errShortDST = internal.ParameterError("DST is shorter than recommended length")

// ExpandXMD expands the input and dst using the given fixed length hash function.
func ExpandXMD(id crypto.Hash, input, dst []byte, length int) []byte {
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			panic(errZeroLenDST)
		}
		// panic(errShortDST)
	}

	return expandXMD(id, input, dst, length)
}

// ExpandXOF expands the input and dst using the given extensible output hash function.
func ExpandXOF(id x.Extensible, input, dst []byte, length int) []byte {
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			panic(errZeroLenDST)
		}
		// panic(errShortDST)
	}

	return expandXOF(id, input, dst, length)
}

func _hash(h hash.Hash, input ...[]byte) []byte {
	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(nil)
}
