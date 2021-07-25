// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ristretto allows simple and abstracted operations in the Ristretto255 group
package ristretto

import "github.com/bytemare/cryptotools/internal"

var (
	errParamNilScalar    = internal.ParameterError("nil or empty scalar")
	errParamScalarLength = internal.ParameterError("invalid scalar length")
	errParamNilPoint     = internal.ParameterError("nil or empty point")
	errCastElement       = internal.ParameterError("could not cast to same group element : wrong group ?")
	errCastScalar        = internal.ParameterError("could not cast to same group scalar : wrong group ?")
)
