// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package other wraps an hash-to-curve implementation and exposes functions for operations on points and scalars.
package other

import (
	"errors"
)

var (
	errParamDecXExceeds     = errors.New("invalid point decompression ( x exceeds order)")
	errParamYNotSquare      = errors.New("y coordinate is not a square mod p")
	errParamNotOnCurve      = errors.New("point is not on curve")
	errParamNilScalar       = errors.New("nil or empty scalar")
	errParamNegScalar       = errors.New("negative scalar")
	errParamScalarTooBig    = errors.New("scalar too big")
	errParamNotRandomOracle = errors.New("function is not indifferentiable from a random oracle")
	errParamDecPoint        = errors.New("could not decode point")
	errParamInvalidSize     = errors.New("invalid input size")
	errParamInvalidFormat   = errors.New("invalid format (uncompressed)")
)
