// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package h2r provides hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
package expand

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/cryptotools/hash"
)

const (
	dstMaxLength  = 255
	dstLongPrefix = "H2C-OVERSIZE-DST-"
)

// var (
// 	errZeroLenDST = internal.ParameterError("zero-length DST")
// 	errShortDST   = internal.ParameterError("DST is shorter than recommended length")
// )

func New(id hash.Identifier) Expander {
	if !id.Extensible() {
		return &XMD{id.(hash.Hashing)}
	}

	return &XOF{id.(hash.Extensible)}
}

func ExpandMessage(id hash.Identifier, input, dst []byte, length int) []byte {
	// todo bring this back after testing
	// if len(h.dst) < group.DstRecommendedMinLength {
	// 	if len(h.dst) == group.DstMinLength {
	// 		panic(errZeroLenDST)
	// 	}
	// 	panic(errShortDST)
	// }
	//h := XMD{Hashing: hash.SHA512}
	return New(id).ExpandMessage(input, dst, length)
}

type Expander interface {
	ExpandMessage(input, dst []byte, length int) []byte
	vetDST(dst []byte) []byte
}

func msgPrime(h hash.Identifier, input, dst []byte, length int) []byte {
	lib := encoding.I2OSP(length, 2)
	dstPrime := dstPrime(dst)

	if h.Extensible() {
		return utils.Concatenate(0, input, lib, dstPrime)
	}

	zPad := make([]byte, h.BlockSize())
	zeroByte := []byte{0}

	return utils.Concatenate(0, zPad, input, lib, zeroByte, dstPrime)
}
