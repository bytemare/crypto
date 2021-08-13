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
	H2C "github.com/armfazh/h2c-go-ref"

	"github.com/bytemare/crypto/group/internal"
)

// Hash2Curve implements the Group interface to Hash-to-Curve primitives.
type Hash2Curve struct {
	suite H2C.SuiteID
}

// New returns a pointer to a Hash2Curve structure instantiated for the given Hash-to-Curve identifier.
// and the domain separation tag.
func New(id H2C.SuiteID) *Hash2Curve {
	h, err := id.Get(nil)
	if err != nil {
		panic(err)
	}

	if !h.IsRandomOracle() {
		panic(errParamNotRandomOracle)
	}

	return &Hash2Curve{id}
}

// NewScalar returns a new, empty, scalar.
func (h *Hash2Curve) NewScalar() internal.Scalar {
	h2 := getH2C(h.suite, nil)

	return scalar(h2.GetHashToScalar().GetScalarField())
}

// ElementLength returns the byte size of an encoded element.
func (h *Hash2Curve) ElementLength() int {
	h2 := getH2C(h.suite, nil)

	return pointLen(h2.GetCurve().Field().BitLen())
}

// NewElement returns a new, empty, element.
func (h *Hash2Curve) NewElement() internal.Point {
	h2 := getH2C(h.suite, nil)

	return &Point{
		Hash2Curve: h,
		curve:      getCurve(h.suite),
		point:      curves[h.suite].New(h2.GetCurve()).base,
	}
}

// Identity returns the group's identity element.
func (h *Hash2Curve) Identity() internal.Point {
	h2 := getH2C(h.suite, nil)

	return &Point{
		Hash2Curve: h,
		curve:      getCurve(h.suite),
		point:      h2.GetCurve().Identity(),
	}
}

func getH2C(id H2C.SuiteID, dst []byte) H2C.HashToPoint {
	h, err := id.Get(dst)
	if err != nil {
		panic(err)
	}

	if !h.IsRandomOracle() {
		panic(errParamNotRandomOracle)
	}

	return h
}

func getCurve(id H2C.SuiteID) *curve {
	h2 := getH2C(id, nil)
	return curves[id].New(h2.GetCurve())
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
func (h *Hash2Curve) HashToGroup(input, dst []byte) internal.Point {
	h2 := getH2C(h.suite, dst)

	return &Point{
		Hash2Curve: h,
		curve:      getCurve(h.suite),
		point:      h2.Hash(input),
	}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (h *Hash2Curve) HashToScalar(input, dst []byte) internal.Scalar {
	h2 := getH2C(h.suite, dst)

	return &Scalar{
		s: h2.GetHashToScalar().Hash(input),
		f: h2.GetHashToScalar().GetScalarField(),
	}
}

// Base returns the group's base point a.k.a. canonical generator.
func (h *Hash2Curve) Base() internal.Point {
	return h.NewElement()
}

// MultBytes allows []byte encodings of a scalar and an element of the Group to be multiplied.
func (h *Hash2Curve) MultBytes(scalar, element []byte) (internal.Point, error) {
	s, err := h.NewScalar().Decode(scalar)
	if err != nil {
		return nil, err
	}

	e, err := h.NewElement().Decode(element)
	if err != nil {
		return nil, err
	}

	return e.Mult(s), nil
}

// func (h *Hash2Curve) checkDSTLen() {
// 	 // todo bring this back after testing
// 	 if len(h.dst) < group.DstRecommendedMinLength {
// 	 	if len(h.dst) == group.DstMinLength {
// 	 		panic(errParamZeroLenDST)
// 	 	}
//
// 	 	panic(errParamShortDST)
// 	 }
// }
