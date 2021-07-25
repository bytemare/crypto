// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package hash2curve wraps an hash-to-curve implementation and exposes functions for operations on points and scalars.
package hash2curve

import "github.com/bytemare/cryptotools/internal"

var (
	errParamInvalidEd25519Enc = internal.ParameterError("invalid Ed25519 encoding")
	errParamDecXExceeds       = internal.ParameterError("invalid point decompression ( x exceeds order)")
	errParamXNotSquare        = internal.ParameterError("x coordinate is not a square mod p")
	errParamYNotSquare        = internal.ParameterError("y coordinate is not a square mod p")
	errParamNotOnCurve        = internal.ParameterError("point is not on curve")
	errParamNilScalar         = internal.ParameterError("nil or empty scalar")
	errParamNegScalar         = internal.ParameterError("negative scalar")
	errParamScalarTooBig      = internal.ParameterError("scalar too big")
	errParamNotRandomOracle   = internal.ParameterError("function is not indifferentiable from a random oracle")
	errParamDecPoint          = internal.ParameterError("could not decode point")
	errParamInvalidSize       = internal.ParameterError("invalid input size")
	errParamInvalidFormat     = internal.ParameterError("invalid format (uncompressed)")
	//errParamZeroLenDST        = internal.ParameterError("zero-length DST")
	//errParamShortDST          = internal.ParameterError("DST is shorter than recommended length")
)
