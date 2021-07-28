// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import "github.com/bytemare/cryptotools/internal"

var (
	ErrParamNilScalar    = internal.ParameterError("nil or empty scalar")
	ErrParamScalarLength = internal.ParameterError("invalid scalar length")
	ErrParamNilPoint     = internal.ParameterError("nil or empty point")
	ErrCastElement       = internal.ParameterError("could not cast to same group element : wrong group ?")
	ErrCastScalar        = internal.ParameterError("could not cast to same group scalar : wrong group ?")
)
