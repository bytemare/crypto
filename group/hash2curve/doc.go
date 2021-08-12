// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package hash2curve provides hash-to-curve compatible hashing over arbitrary input.
//
// Currently, it is specifically suited for hashing to Ristretto255, Curve25519, and Edwards25519.
// It implements the latest hash-to-curve specification to date (https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11).
package hash2curve
