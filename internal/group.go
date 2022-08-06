// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

// Group abstracts operations in a prime-order group.
type Group interface {
	// NewScalar returns a new, empty, scalar.
	NewScalar() Scalar

	// NewElement returns the identity point (point at infinity).
	NewElement() Element

	// Base returns the group's base point a.k.a. canonical generator.
	Base() Element

	// HashToScalar allows arbitrary input to be safely mapped to the field.
	HashToScalar(input, dst []byte) Scalar

	// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
	HashToGroup(input, dst []byte) Element

	// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
	EncodeToGroup(input, dst []byte) Element

	// Ciphersuite returns the hash-to-curve ciphersuite identifier.
	Ciphersuite() string

	// ScalarLength returns the byte size of an encoded scalar.
	ScalarLength() uint

	// ElementLength returns the byte size of an encoded element.
	ElementLength() uint
}
