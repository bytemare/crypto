// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

const (
	// DstMinLength is the minimum acceptable length of input DST.
	DstMinLength = 0

	// DstRecommendedMinLength is the minimum recommended length of input DST.
	DstRecommendedMinLength = 16
)

// Group abstracts operations in elliptic-curve prime-order groups.
type Group interface {
	// NewScalar returns a new, empty, scalar.
	NewScalar() Scalar

	// NewElement returns a new, empty, element.
	NewElement() Point

	// ElementLength returns the byte size of an encoded element.
	ElementLength() int

	// Identity returns the group's identity element.
	Identity() Point

	// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
	HashToGroup(input, dst []byte) Point

	// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
	EncodeToGroup(input, dst []byte) Point

	// HashToScalar allows arbitrary input to be safely mapped to the field.
	HashToScalar(input, dst []byte) Scalar

	// Base returns the group's base point a.k.a. canonical generator.
	Base() Point

	// MultBytes allows []byte encodings of a scalar and an element of the Group to be multiplied.
	MultBytes(scalar, element []byte) (Point, error)
}
